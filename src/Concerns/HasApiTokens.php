<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Concerns;

use Cline\Bearer\Contracts\HasAbilities;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\NewAccessToken;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Attributes\Boot;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;

use function method_exists;

/**
 * Trait for models that can own and manage API tokens.
 *
 * This trait implements the HasApiTokens contract, providing comprehensive token
 * management capabilities for any Eloquent model (typically User models). It enables
 * models to create, manage, and authenticate via personal access tokens with fine-grained
 * permission control.
 *
 * Key features:
 * - Create individual tokens or token groups with specific abilities
 * - Support for multiple token types (secret, publishable, restricted)
 * - Environment-based token separation (production, development, staging)
 * - Track the currently active token during authenticated requests
 * - Check token abilities and characteristics during runtime
 * - Organize related tokens into logical groups
 *
 * Example usage:
 * ```php
 * use Cline\Bearer\Concerns\HasApiTokens;
 * use Cline\Bearer\Contracts\HasApiTokens as HasApiTokensContract;
 *
 * class User extends Model implements HasApiTokensContract
 * {
 *     use HasApiTokens;
 * }
 *
 * // Create a single token
 * $token = $user->createToken(
 *     type: 'secret_key',
 *     name: 'API Access',
 *     abilities: ['users:read', 'posts:write'],
 *     environment: 'production',
 *     expiresAt: now()->addYear(),
 *     metadata: ['client_id' => 'app-123']
 * );
 *
 * // Create a token group with multiple related tokens
 * $group = $user->createAccessTokenGroup(
 *     types: ['secret_key', 'publishable_key'],
 *     name: 'Payment Processing',
 *     abilities: ['payments:process', 'webhooks:receive'],
 *     environment: 'production',
 *     metadata: ['integration' => 'stripe']
 * );
 *
 * // Check token abilities during request
 * if ($user->tokenCan('users:write')) {
 *     // User's current token has write permission
 * }
 *
 * // Check token type
 * if ($user->tokenIs('secret_key')) {
 *     // User authenticated with a secret key
 * }
 *
 * // Get token environment
 * if ($user->tokenEnvironment() === 'production') {
 *     // Token is for production use
 * }
 * ```
 *
 * Common patterns:
 * ```php
 * // Creating scoped tokens for different purposes
 * $readToken = $user->createToken(
 *     type: 'restricted_key',
 *     name: 'Read Only',
 *     abilities: ['users:read', 'posts:read']
 * );
 *
 * $adminToken = $user->createToken(
 *     type: 'secret_key',
 *     name: 'Admin Access',
 *     abilities: ['*']
 * );
 *
 * // Managing tokens via relationships
 * $user->tokens()->where('environment', 'production')->get();
 * $user->tokens()->where('type', 'secret_key')->delete();
 *
 * // Working with token groups
 * $group = $user->tokenGroups()->create(['name' => 'Mobile App']);
 * $secretKey = $group->secretKey();
 * $publishableKey = $group->publishableKey();
 * ```
 *
 * @template TToken of \Cline\Bearer\Contracts\HasAbilities
 *
 * @mixin Model
 *
 * @author Brian Faust <brian@cline.sh>
 */
trait HasApiTokens
{
    /**
     * The access token the user is using for the current request.
     *
     * Set by the authentication guard when a request is successfully authenticated
     * via a token. Used to check permissions and characteristics of the token
     * being used for the current operation.
     *
     * @var null|TToken
     */
    protected ?HasAbilities $accessToken = null;

    /**
     * Boot the HasApiTokens trait.
     *
     * Registers model event listeners for cascade deletion of tokens
     * when the tokenable model is deleted.
     */
    #[Boot()]
    public static function cascadeDeleteTokens(): void
    {
        static::deleting(static function (Model $model): void {
            if (method_exists($model, 'tokens')) {
                $model->tokens()->delete();
            }

            if (method_exists($model, 'tokenGroups')) {
                $model->tokenGroups()->delete();
            }
        });
    }

    /**
     * Get all access tokens that belong to this model.
     *
     * Returns a polymorphic relationship to AccessToken models, allowing
     * full Eloquent query capabilities for filtering, creating, updating, and
     * deleting tokens associated with this tokenable entity.
     *
     * Example usage:
     * ```php
     * // Get all active tokens
     * $activeTokens = $user->tokens()
     *     ->whereNull('revoked_at')
     *     ->where('expires_at', '>', now())
     *     ->get();
     *
     * // Get tokens by type
     * $secretKeys = $user->tokens()->where('type', 'secret_key')->get();
     *
     * // Create a new token directly
     * $token = $user->tokens()->create([
     *     'type' => 'secret_key',
     *     'name' => 'Direct Creation',
     *     'token' => hash('sha256', $plaintext),
     *     'abilities' => ['*'],
     * ]);
     * ```
     *
     * @return MorphMany<AccessToken, $this> Relationship to AccessToken models
     */
    public function tokens(): MorphMany
    {
        return $this->morphMany(
            Bearer::personalAccessTokenModel(),
            'tokenable',
        );
    }

    /**
     * Get all token groups that belong to this model.
     *
     * Returns a polymorphic relationship to AccessTokenGroup models, enabling logical
     * organization of related tokens. Token groups are useful for managing sets
     * of tokens that work together, such as secret/publishable key pairs.
     *
     * Example usage:
     * ```php
     * // Get all token groups
     * $groups = $user->tokenGroups()->get();
     *
     * // Find a specific group
     * $mobileGroup = $user->tokenGroups()
     *     ->where('name', 'Mobile App')
     *     ->first();
     *
     * // Get tokens from a group
     * foreach ($user->tokenGroups as $group) {
     *     $secretKey = $group->secretKey();
     *     $publishableKey = $group->publishableKey();
     * }
     * ```
     *
     * @return MorphMany<AccessTokenGroup, $this> Relationship to AccessTokenGroup models
     */
    public function tokenGroups(): MorphMany
    {
        /** @var class-string<AccessTokenGroup> $model */
        $model = Bearer::tokenGroupModel();

        return $this->morphMany($model, 'owner');
    }

    /**
     * Create a new personal access token for this model.
     *
     * Generates and persists a new token with the specified characteristics.
     * Returns a NewAccessToken instance containing both the database model
     * and the plain-text token value (which is only available once).
     *
     * The token type determines its purpose and restrictions:
     * - 'secret_key': Full access, server-side only
     * - 'publishable_key': Limited access, client-side safe
     * - 'restricted_key': Custom restricted access
     *
     * Example usage:
     * ```php
     * // Create a standard API token
     * $token = $user->createToken(
     *     type: 'secret_key',
     *     name: 'Production API',
     *     abilities: ['users:read', 'posts:write'],
     *     environment: 'production',
     *     expiresAt: now()->addMonths(6),
     *     metadata: ['created_by' => 'admin-panel']
     * );
     *
     * // The plain text token is only available in the response
     * $plainTextToken = $token->plainTextToken;
     * // Store this securely - it won't be accessible again!
     *
     * // The persisted token model is also available
     * $tokenModel = $token->accessToken;
     * ```
     *
     * @param  string                 $type        Token type (e.g., 'secret_key', 'publishable_key')
     * @param  string                 $name        Human-readable token name for identification
     * @param  array<int, string>     $abilities   Token abilities/permissions (e.g., ['users:read', 'posts:write'])
     * @param  null|string            $environment Token environment (e.g., 'production', 'development')
     * @param  null|DateTimeInterface $expiresAt   Optional expiration timestamp
     * @param  array<string, mixed>   $metadata    Optional arbitrary metadata for application use
     * @return NewAccessToken         Object containing the persisted token and plain-text value
     */
    public function createToken(
        string $type,
        string $name,
        array $abilities = [],
        ?string $environment = null,
        ?DateTimeInterface $expiresAt = null,
        array $metadata = [],
    ): NewAccessToken {
        return Bearer::for($this)->issue(
            type: $type,
            name: $name,
            abilities: $abilities,
            environment: $environment,
            expiresAt: $expiresAt,
            metadata: $metadata,
        );
    }

    /**
     * Create a token group with multiple related tokens.
     *
     * Generates a group of related tokens (e.g., secret/publishable key pairs)
     * that share the same name, abilities, and metadata. This is useful for
     * creating coordinated token sets for integrations or applications.
     *
     * All tokens in the group will:
     * - Share the same group_id for relationship queries
     * - Have identical abilities and environment settings
     * - Be revocable together via the group
     *
     * Example usage:
     * ```php
     * // Create a payment processing token group
     * $group = $user->createAccessTokenGroup(
     *     types: ['secret_key', 'publishable_key'],
     *     name: 'Stripe Integration',
     *     abilities: ['payments:process', 'webhooks:receive'],
     *     environment: 'production',
     *     metadata: ['integration_id' => 'stripe_123']
     * );
     *
     * // Access individual tokens from the group
     * $secretKey = $group->secretKey();
     * $publishableKey = $group->publishableKey();
     *
     * // Revoke all tokens in the group
     * $group->revokeAll();
     * ```
     *
     * @param  array<int, string>   $types       Array of token types to create in the group
     * @param  string               $name        Human-readable group name shared by all tokens
     * @param  array<int, string>   $abilities   Token abilities shared by all tokens in the group
     * @param  null|string          $environment Token environment shared by all tokens
     * @param  array<string, mixed> $metadata    Optional metadata shared by all tokens
     * @return AccessTokenGroup     The created token group with all tokens accessible
     */
    public function createAccessTokenGroup(
        array $types,
        string $name,
        array $abilities = [],
        ?string $environment = null,
        array $metadata = [],
    ): AccessTokenGroup {
        return Bearer::for($this)->issueGroup(
            types: $types,
            name: $name,
            abilities: $abilities,
            environment: $environment,
            metadata: $metadata,
        );
    }

    /**
     * Get the access token currently associated with this model.
     *
     * During an authenticated request, returns the token instance that was used
     * to authenticate. This is set by the authentication guard after successful
     * token validation and can be used to check the token's characteristics.
     *
     * Returns null when:
     * - The user is authenticated via session (not token)
     * - No authentication has occurred
     * - Called outside of a request context
     *
     * Example usage:
     * ```php
     * $currentToken = $user->currentAccessToken();
     *
     * if ($currentToken) {
     *     // Check token properties
     *     $abilities = $currentToken->abilities;
     *     $expiresAt = $currentToken->expires_at;
     *
     *     // Token-specific logic
     *     if ($currentToken instanceof AccessToken) {
     *         $tokenType = $currentToken->type;
     *         $environment = $currentToken->environment;
     *     }
     * }
     * ```
     *
     * @return null|TToken The current token instance, or null if not authenticated via token
     */
    public function currentAccessToken(): ?HasAbilities
    {
        return $this->accessToken;
    }

    /**
     * Set the current access token for this model.
     *
     * Associates a token instance with this model for the duration of the request.
     * This is typically called by authentication guards during the authentication
     * process and should rarely need to be called manually.
     *
     * The token is stored as an instance property and is not persisted to the
     * database. It exists only for the current request lifecycle.
     *
     * Example usage:
     * ```php
     * // Typically called by guards, not manually
     * $user->withAccessToken($authenticatedToken);
     *
     * // Now token methods work
     * $user->tokenCan('users:read'); // Uses the set token
     * ```
     *
     * @param  TToken $accessToken The authenticated token instance
     * @return static Fluent interface for method chaining
     */
    public function withAccessToken(HasAbilities $accessToken): static
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * Determine if the current token has a given ability.
     *
     * Convenience method that checks if the currently associated token (if any)
     * has the specified ability. Returns false if no token is currently associated,
     * making it safe to call without null checks.
     *
     * This is particularly useful in authorization logic and middleware where
     * you need to verify token-specific permissions.
     *
     * Example usage:
     * ```php
     * // In a controller
     * if (!$user->tokenCan('posts:write')) {
     *     abort(403, 'This token lacks write permissions');
     * }
     *
     * // In authorization logic
     * Gate::define('edit-post', function ($user) {
     *     return $user->tokenCan('posts:write');
     * });
     *
     * // In middleware
     * if ($request->user()->tokenCan('admin:access')) {
     *     // Proceed with admin operation
     * }
     * ```
     *
     * @param  string $ability The ability to check (e.g., 'users:read', 'posts:write')
     * @return bool   True if current token has this ability, false otherwise
     */
    public function tokenCan(string $ability): bool
    {
        return $this->accessToken?->can($ability) ?? false;
    }

    /**
     * Determine if the current token is missing a given ability.
     *
     * Inverse of tokenCan(), providing a more expressive API for checking
     * the absence of permissions. Returns true if no token is currently
     * associated or if the token lacks the specified ability.
     *
     * This makes authorization logic more readable by expressing restrictions
     * in a positive way.
     *
     * Example usage:
     * ```php
     * // More expressive than !tokenCan()
     * if ($user->tokenCant('admin:delete')) {
     *     throw new UnauthorizedException('Admin deletion not permitted');
     * }
     *
     * // In validation logic
     * if ($user->tokenCant('payments:process')) {
     *     return response()->json([
     *         'error' => 'Token lacks payment processing permissions'
     *     ], 403);
     * }
     * ```
     *
     * @param  string $ability The ability to check for absence
     * @return bool   True if the token lacks this ability, false if it has it
     */
    public function tokenCant(string $ability): bool
    {
        return !$this->tokenCan($ability);
    }

    /**
     * Determine if the current token is of a specific type.
     *
     * Checks whether the currently associated token matches the given type.
     * Returns false if no token is associated or if the token is not a
     * AccessToken instance.
     *
     * Common token types:
     * - 'secret_key': Server-side API keys with full access
     * - 'publishable_key': Client-side safe keys with limited access
     * - 'restricted_key': Custom restricted access keys
     *
     * Example usage:
     * ```php
     * // Enforce server-side only operations
     * if (!$user->tokenIs('secret_key')) {
     *     abort(403, 'This operation requires a secret key');
     * }
     *
     * // Different behavior based on token type
     * if ($user->tokenIs('publishable_key')) {
     *     // Apply client-side restrictions
     *     $data = $this->getPublicData();
     * } else {
     *     $data = $this->getFullData();
     * }
     *
     * // Audit logging
     * if ($user->tokenIs('restricted_key')) {
     *     Log::info('Restricted key used', [
     *         'user_id' => $user->id,
     *         'action' => $action
     *     ]);
     * }
     * ```
     *
     * @param  string $type The token type to check (e.g., 'secret_key', 'publishable_key')
     * @return bool   True if current token matches the type, false otherwise
     */
    public function tokenIs(string $type): bool
    {
        if (!$this->accessToken instanceof AccessToken) {
            return false;
        }

        return $this->accessToken->type === $type;
    }

    /**
     * Get the current token's environment.
     *
     * Returns the environment designation of the currently associated token,
     * or null if no AccessToken is associated.
     *
     * Common environments:
     * - 'production': Live production use
     * - 'development': Development and testing
     * - 'staging': Pre-production staging
     *
     * Example usage:
     * ```php
     * // Environment-specific behavior
     * if ($user->tokenEnvironment() === 'production') {
     *     // Use production services
     *     $service = new ProductionPaymentService();
     * } else {
     *     // Use sandbox for testing
     *     $service = new SandboxPaymentService();
     * }
     *
     * // Validation
     * if ($user->tokenEnvironment() !== config('app.env')) {
     *     throw new InvalidEnvironmentException(
     *         "Token environment mismatch"
     *     );
     * }
     *
     * // Audit logging
     * Log::info('API request', [
     *     'user_id' => $user->id,
     *     'environment' => $user->tokenEnvironment(),
     *     'endpoint' => $request->path()
     * ]);
     * ```
     *
     * @return null|string The token's environment, or null if no token is set
     */
    public function tokenEnvironment(): ?string
    {
        if (!$this->accessToken instanceof AccessToken) {
            return null;
        }

        return $this->accessToken->environment;
    }

    /**
     * Get the current token's type.
     *
     * Returns the type designation of the currently associated token,
     * or null if no AccessToken is associated.
     *
     * This is useful when you need to inspect the token type for logging,
     * analytics, or conditional logic without using tokenIs() for specific
     * type comparisons.
     *
     * Example usage:
     * ```php
     * // Logging and analytics
     * Log::info('API access', [
     *     'user_id' => $user->id,
     *     'token_type' => $user->tokenType(),
     *     'endpoint' => $request->path()
     * ]);
     *
     * // Dynamic behavior based on type
     * $rateLimit = match ($user->tokenType()) {
     *     'secret_key' => 1000,
     *     'publishable_key' => 100,
     *     'restricted_key' => 50,
     *     default => 10,
     * };
     *
     * // Response headers
     * return response()->json($data)->header(
     *     'X-Token-Type',
     *     $user->tokenType() ?? 'none'
     * );
     * ```
     *
     * @return null|string The token's type (e.g., 'secret_key'), or null if no token is set
     */
    public function tokenType(): ?string
    {
        if (!$this->accessToken instanceof AccessToken) {
            return null;
        }

        return $this->accessToken->type;
    }
}
