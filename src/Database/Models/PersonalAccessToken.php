<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Database\Models;

use Cline\Keychain\Contracts\HasAbilities;
use Cline\Keychain\Database\Concerns\HasKeychainPrimaryKey;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Override;

use function array_flip;
use function array_key_exists;
use function in_array;
use function now;

/**
 * Eloquent model representing API access tokens.
 *
 * Stores individual API tokens with their associated metadata, abilities,
 * restrictions, and relationships. Implements ability-based authorization
 * and provides token validation methods.
 *
 * @property array<int, string>        $abilities             Token abilities/permissions
 * @property null|array<int, string>   $allowed_domains       Domain whitelist
 * @property null|array<int, string>   $allowed_ips           IP whitelist
 * @property Carbon                    $created_at            Record creation timestamp
 * @property string                    $environment           Token environment (production, development, etc.)
 * @property null|Carbon               $expires_at            Expiration timestamp
 * @property null|TokenGroup           $group                 Token group this token belongs to
 * @property null|int|string           $group_id              Token group ID for linking related tokens
 * @property mixed                     $id                    Primary key (auto-increment, UUID, or ULID)
 * @property null|Carbon               $last_used_at          Last usage timestamp
 * @property null|array<string, mixed> $metadata              Optional arbitrary metadata
 * @property string                    $name                  Human-readable token name
 * @property string                    $prefix                Token prefix for identification
 * @property null|int                  $rate_limit_per_minute Rate limit threshold
 * @property null|Carbon               $revoked_at            Revocation timestamp
 * @property string                    $token                 Hashed token value
 * @property null|Model                $tokenable             The polymorphic model this token belongs to
 * @property string                    $tokenable_id          Polymorphic ID of the token owner
 * @property string                    $tokenable_type        Polymorphic type of the token owner
 * @property string                    $type                  Token type (secret_key, publishable_key, etc.)
 * @property Carbon                    $updated_at            Record last modification timestamp
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PersonalAccessToken extends Model implements HasAbilities
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasKeychainPrimaryKey;

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'abilities' => 'json',
        'metadata' => 'json',
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
     * Get the table name from configuration.
     *
     * Retrieves the personal_access_tokens table name from the Keychain configuration,
     * defaulting to 'personal_access_tokens' if not configured.
     *
     * @return string The table name for token storage
     */
    #[Override()]
    public function getTable(): string
    {
        /** @var string */
        return Config::get('keychain.table_names.personal_access_tokens', 'personal_access_tokens');
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
     * Defines the relationship to the TokenGroup that links related tokens together.
     *
     * @return BelongsTo<TokenGroup, $this> The relationship to the token group
     */
    public function group(): BelongsTo
    {
        return $this->belongsTo(TokenGroup::class, 'group_id');
    }

    /**
     * Get all audit logs for this token.
     *
     * Defines the relationship to TokenAuditLog entries that track this token's
     * activity history, security events, and usage patterns.
     *
     * @return HasMany<TokenAuditLog, $this> The relationship to audit log entries
     */
    public function auditLogs(): HasMany
    {
        return $this->hasMany(TokenAuditLog::class, 'token_id');
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
     * @return bool True if the token has an expiration date and it has passed
     */
    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    /**
     * Check if the token is revoked.
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
     * A token is valid if it is neither expired nor revoked.
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
     * Useful for getting related tokens, e.g., finding the secret_key
     * when you have the publishable_key.
     *
     * @param  string    $type The type of sibling token to retrieve
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
     * Sets the revoked_at timestamp to mark the token as invalid.
     *
     * @return bool True if the revocation was successful
     */
    public function revoke(): bool
    {
        $this->revoked_at = now();

        return $this->save();
    }
}
