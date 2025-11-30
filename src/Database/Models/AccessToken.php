<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Database\Models;

use Cline\Ancestry\Concerns\HasAncestry;
use Cline\Bearer\Contracts\HasAbilities;
use Cline\Bearer\Database\Concerns\HasBearerPrimaryKey;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;
use Override;

use function array_diff;
use function array_flip;
use function array_key_exists;
use function in_array;
use function now;

/**
 * Eloquent model representing API access tokens.
 *
 * This is the core model for token storage and management. Each token represents
 * a unique API credential with configurable permissions (abilities), restrictions
 * (IP/domain whitelisting), lifecycle management (expiration, revocation), and
 * hierarchical relationships (token derivation).
 *
 * Key features:
 * - Ability-based authorization with wildcard support
 * - Token grouping for related tokens (e.g., secret/publishable key pairs)
 * - Hierarchical token derivation for delegated access
 * - IP and domain whitelisting for security
 * - Rate limiting per token
 * - Environment scoping (test/live separation)
 * - Comprehensive audit logging integration
 *
 * @property array<int, string>        $abilities             Token abilities/permissions (e.g., ['api:read', 'api:write'])
 * @property null|array<int, string>   $allowed_domains       Domain whitelist for CORS-like restrictions
 * @property null|array<int, string>   $allowed_ips           IP whitelist for network-based access control
 * @property Carbon                    $created_at            Record creation timestamp
 * @property string                    $environment           Token environment ('test' or 'live')
 * @property null|Carbon               $expires_at            Token expiration timestamp (null for non-expiring)
 * @property null|AccessTokenGroup     $group                 Token group this token belongs to
 * @property null|int|string           $group_id              Foreign key to access_token_groups table
 * @property mixed                     $id                    Primary key (auto-increment, UUID, or ULID)
 * @property null|Carbon               $last_used_at          Last successful authentication timestamp
 * @property null|array<string, mixed> $metadata              Optional arbitrary JSON metadata
 * @property string                    $name                  Human-readable token name/description
 * @property string                    $prefix                Token prefix for visual identification (e.g., 'sk', 'pk')
 * @property null|int                  $rate_limit_per_minute Rate limit threshold (requests per minute)
 * @property null|Carbon               $revoked_at            Revocation timestamp (null for active tokens)
 * @property string                    $token                 Hashed token value (never exposed in responses)
 * @property null|Model                $tokenable             The polymorphic model owning this token
 * @property string                    $tokenable_id          Polymorphic foreign key ID
 * @property string                    $tokenable_type        Polymorphic foreign key type
 * @property string                    $type                  Token type identifier (e.g., 'secret_key', 'publishable_key')
 * @property Carbon                    $updated_at            Record last modification timestamp
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AccessToken extends Model implements HasAbilities
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasBearerPrimaryKey;
    use HasAncestry;

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'abilities' => 'json',
        'metadata' => 'json',
        'derived_metadata' => 'json',
        'allowed_ips' => 'json',
        'allowed_domains' => 'json',
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'group_id',
        'type',
        'environment',
        'name',
        'token',
        'prefix',
        'abilities',
        'metadata',
        'derived_metadata',
        'allowed_ips',
        'allowed_domains',
        'rate_limit_per_minute',
        'expires_at',
        'revoked_at',
        'last_used_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'token',
    ];

    /**
     * Check if a set of abilities is a subset of another.
     *
     * Determines whether all abilities in the child set are present in the
     * parent set. If the parent has the wildcard '*' ability, all child
     * abilities are considered valid. Useful for validating token derivation
     * and delegation scenarios.
     *
     * @param  array<int, string> $childAbilities  The abilities to validate
     * @param  array<int, string> $parentAbilities The abilities to validate against
     * @return bool               True if all child abilities exist in parent abilities
     */
    public static function areAbilitiesSubset(array $childAbilities, array $parentAbilities): bool
    {
        if (in_array('*', $parentAbilities, true)) {
            return true;
        }

        return array_diff($childAbilities, $parentAbilities) === [];
    }

    /**
     * Get the table name from configuration.
     *
     * Retrieves the access_tokens table name from the Bearer configuration,
     * defaulting to 'access_tokens' if not configured.
     *
     * @return string The table name for token storage
     */
    #[Override()]
    public function getTable(): string
    {
        /** @var string */
        return Config::get('bearer.table_names.access_tokens', 'access_tokens');
    }

    /**
     * Get the tokenable model that the access token belongs to.
     *
     * Defines the relationship to the model that owns this token,
     * such as a User or Organization.
     *
     * @return MorphTo<Model, $this> The polymorphic relationship to the owning entity
     */
    public function tokenable(): MorphTo
    {
        return $this->morphTo('tokenable');
    }

    /**
     * Get the token group this token belongs to.
     *
     * Defines the relationship to the AccessTokenGroup that links related tokens together.
     *
     * @return BelongsTo<AccessTokenGroup, $this> The relationship to the token group
     */
    public function group(): BelongsTo
    {
        return $this->belongsTo(AccessTokenGroup::class, 'group_id');
    }

    /**
     * Get all audit logs for this token.
     *
     * Defines the relationship to AccessTokenAuditLog entries that track this token's
     * activity history, security events, and usage patterns.
     *
     * @return HasMany<AccessTokenAuditLog, $this> The relationship to audit log entries
     */
    public function auditLogs(): HasMany
    {
        return $this->hasMany(AccessTokenAuditLog::class, 'token_id');
    }

    /**
     * Determine if the token has a given ability.
     *
     * Checks whether the token possesses the specified ability/permission.
     * The wildcard ability '*' grants all permissions.
     *
     * @param  string $ability The ability to check (e.g., 'users:read', 'posts:write')
     * @return bool   True if the token has this ability, false otherwise
     */
    #[Override()]
    public function can(string $ability): bool
    {
        return in_array('*', $this->abilities, true)
               || array_key_exists($ability, array_flip($this->abilities));
    }

    /**
     * Determine if the token is missing a given ability.
     *
     * Inverse of can(). Provides a more expressive API for checking the absence
     * of permissions.
     *
     * @param  string $ability The ability to check for absence
     * @return bool   True if the token lacks this ability, false if it has it
     */
    #[Override()]
    public function cant(string $ability): bool
    {
        return !$this->can($ability);
    }

    /**
     * Check if the token is expired.
     *
     * Tokens with no expiration date (expires_at is null) never expire.
     * Tokens with a future expiration are still valid.
     *
     * @return bool True if the token has an expiration date and it has passed
     */
    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * Check if the token is revoked.
     *
     * Revoked tokens cannot be used for authentication even if they haven't
     * expired. Revocation is permanent and cannot be undone.
     *
     * @return bool True if the token has been explicitly revoked
     */
    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    /**
     * Check if the token is valid for use.
     *
     * A token is valid if it is neither expired nor revoked. This is the
     * primary method for determining if a token can be used for authentication.
     * Does not check IP/domain restrictions or rate limits.
     *
     * @return bool True if the token can be used, false otherwise
     */
    public function isValid(): bool
    {
        return !$this->isExpired() && !$this->isRevoked();
    }

    /**
     * Get a sibling token of a specific type from the same group.
     *
     * Retrieves another token from the same group with a different type.
     * Common use case is finding the secret_key when you have the publishable_key
     * in a Stripe-like token pairing scenario. Returns null if this token
     * doesn't belong to a group.
     *
     * @param  string    $type The type of sibling token to retrieve (e.g., 'secret_key')
     * @return null|self The sibling token if found, null otherwise
     */
    public function sibling(string $type): ?self
    {
        if ($this->group_id === null) {
            return null;
        }

        return self::query()->where('group_id', $this->group_id)
            ->where('type', $type)
            ->where($this->getKeyName(), '!=', $this->getKey())
            ->first();
    }

    /**
     * Revoke this token.
     *
     * Sets the revoked_at timestamp to mark the token as invalid and persists
     * the change to the database. Revoked tokens cannot be used for authentication
     * and the operation is permanent.
     *
     * @return bool True if the revocation was successfully saved to the database
     */
    public function revoke(): bool
    {
        $this->revoked_at = now();

        return $this->save();
    }

    /**
     * Check if this token is a root token (has no parent).
     *
     * Root tokens are the top-level tokens in a derivation hierarchy and were
     * not derived from any parent token. They can create child tokens if
     * derivation is enabled.
     *
     * @return bool True if the token has no parent in the derivation hierarchy
     */
    public function isRootToken(): bool
    {
        /** @var string */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');

        return $this->isAncestryRoot($hierarchyType);
    }

    /**
     * Check if this token can derive child tokens.
     *
     * Determines whether this token is eligible to create derived child tokens
     * based on maximum depth configuration, revocation status, and expiration.
     * Tokens cannot derive children if they are revoked, expired, or have
     * reached the maximum derivation depth.
     *
     * @return bool True if the token can derive children based on validity and depth limits
     */
    public function canDeriveTokens(): bool
    {
        $maxDepth = Config::get('bearer.derivation.max_depth', 3);

        /** @var string */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');

        $currentDepth = $this->getAncestryDepth($hierarchyType);

        return $currentDepth < $maxDepth
            && !$this->revoked_at
            && (!$this->expires_at || $this->expires_at->isFuture());
    }

    /**
     * Get the parent token in the derivation hierarchy.
     *
     * Returns the token from which this token was derived. Null for root tokens
     * that were created directly rather than derived from another token.
     *
     * @return null|self The parent token if one exists, null for root tokens
     */
    public function parentToken(): ?self
    {
        /** @var string */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');

        /** @var null|self */
        return $this->getAncestryParent($hierarchyType);
    }

    /**
     * Get all direct child tokens.
     *
     * Returns only the immediate children that were derived from this token.
     * Does not include grandchildren or deeper descendants.
     *
     * @return Collection<int, self> Collection of direct child tokens
     */
    public function childTokens(): Collection
    {
        /** @var string */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');

        /** @var Collection<int, self> */
        return $this->getAncestryChildren($hierarchyType);
    }

    /**
     * Get all descendant tokens (children, grandchildren, etc.).
     *
     * Returns the complete tree of all tokens derived from this token at any
     * depth level. Useful for cascading revocation or analyzing delegation chains.
     *
     * @return Collection<int, self> Collection of all descendant tokens
     */
    public function allDescendantTokens(): Collection
    {
        /** @var string */
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');

        /** @var Collection<int, self> */
        return $this->getAncestryDescendants($hierarchyType);
    }
}
