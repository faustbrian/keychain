<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Database\Models;

use Cline\Keychain\Database\Concerns\HasKeychainPrimaryKey;
use Cline\Keychain\Database\Factories\TokenGroupFactory;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Override;

use function now;

/**
 * Eloquent model representing token groups for linking related tokens.
 *
 * Token groups allow multiple related tokens (e.g., secret_key, publishable_key,
 * restricted_key) to be associated together, enabling operations like batch
 * revocation and sibling token lookups.
 *
 * Common use case: Stripe-like token pairs where a secret key and publishable key
 * belong to the same group, allowing you to revoke all related tokens at once or
 * retrieve sibling tokens for validation.
 *
 * Example usage:
 * ```php
 * $group = TokenGroup::create(['name' => 'Production Keys']);
 * $group->tokens()->create([...secretKeyData...]);
 * $group->tokens()->create([...publishableKeyData...]);
 * $group->revokeAll(); // Revoke all tokens in the group
 * ```
 *
 * @property Carbon                               $created_at Record creation timestamp
 * @property mixed                                $id         Primary key (auto-increment, UUID, or ULID)
 * @property null|array<string, mixed>            $metadata   Optional arbitrary JSON metadata
 * @property string                               $name       Human-readable group name/description
 * @property null|Model                           $owner      The polymorphic model this group belongs to
 * @property string                               $owner_id   Polymorphic foreign key ID
 * @property string                               $owner_type Polymorphic foreign key type
 * @property Collection<int, PersonalAccessToken> $tokens     All tokens belonging to this group
 * @property Carbon                               $updated_at Record last modification timestamp
 *
 * @author Brian Faust <brian@cline.sh>
 */
#[UseFactory(TokenGroupFactory::class)]
final class TokenGroup extends Model
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasKeychainPrimaryKey;

    /**
     * Attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'metadata' => 'json',
    ];

    /**
     * Attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'metadata',
    ];

    /**
     * Get the table name from configuration.
     *
     * Retrieves the token_groups table name from the Keychain configuration,
     * defaulting to 'token_groups' if not configured.
     *
     * @return string The table name for token group storage
     */
    #[Override()]
    public function getTable(): string
    {
        /** @var string */
        return Config::get('keychain.table_names.token_groups', 'token_groups');
    }

    /**
     * Get the owner model that the token group belongs to.
     *
     * Defines the relationship to the model that owns this token group,
     * such as a User or Organization.
     *
     * @return MorphTo<Model, $this> The polymorphic relationship to the owning entity
     */
    public function owner(): MorphTo
    {
        return $this->morphTo('owner');
    }

    /**
     * Get all tokens belonging to this group.
     *
     * Defines the relationship to the PersonalAccessToken models in this group.
     *
     * @return HasMany<PersonalAccessToken, $this> The relationship to the tokens
     */
    public function tokens(): HasMany
    {
        return $this->hasMany(PersonalAccessToken::class, 'group_id');
    }

    /**
     * Get a specific token from this group by type.
     *
     * Retrieves a single token with the specified type identifier from this group.
     * Returns null if no token of the given type exists in the group.
     *
     * @param  string                   $type The token type to retrieve (e.g., 'secret_key', 'pk')
     * @return null|PersonalAccessToken The token if found, null otherwise
     */
    public function token(string $type): ?PersonalAccessToken
    {
        return $this->tokens()->where('type', $type)->first();
    }

    /**
     * Get the secret key token from this group.
     *
     * Convenience method for retrieving the secret key token using the configured
     * type identifier from 'keychain.types.group_helpers.secret'.
     *
     * @return null|PersonalAccessToken The secret key token if found, null otherwise
     */
    public function secretKey(): ?PersonalAccessToken
    {
        /** @var string */
        $type = Config::get('keychain.types.group_helpers.secret', 'sk');

        return $this->token($type);
    }

    /**
     * Get the publishable key token from this group.
     *
     * Convenience method for retrieving the publishable key token using the
     * configured type identifier from 'keychain.types.group_helpers.publishable'.
     *
     * @return null|PersonalAccessToken The publishable key token if found, null otherwise
     */
    public function publishableKey(): ?PersonalAccessToken
    {
        /** @var string */
        $type = Config::get('keychain.types.group_helpers.publishable', 'pk');

        return $this->token($type);
    }

    /**
     * Get the restricted key token from this group.
     *
     * Convenience method for retrieving the restricted key token using the
     * configured type identifier from 'keychain.types.group_helpers.restricted'.
     *
     * @return null|PersonalAccessToken The restricted key token if found, null otherwise
     */
    public function restrictedKey(): ?PersonalAccessToken
    {
        /** @var string */
        $type = Config::get('keychain.types.group_helpers.restricted', 'rk');

        return $this->token($type);
    }

    /**
     * Revoke all tokens in this group.
     *
     * Performs a batch update to set the revoked_at timestamp on all tokens
     * in the group. This is useful for invalidating all related tokens at once,
     * such as when a user requests to revoke all API keys.
     *
     * @return int The number of tokens that were revoked
     */
    public function revokeAll(): int
    {
        return $this->tokens()->update(['revoked_at' => now()]);
    }
}
