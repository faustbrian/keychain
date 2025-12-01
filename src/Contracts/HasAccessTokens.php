<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;

/**
 * Contract for models that can own access tokens.
 *
 * This contract defines the interface for tokenable models (typically User models)
 * that can create, manage, and authenticate via personal access tokens. It provides
 * the foundation for token-based authentication in your application.
 *
 * Bearer uses a three-tier relationship model:
 * - Owner: The entity that created/owns the token (who generated it)
 * - Context: The entity the token acts on behalf of (optional)
 * - Boundary: The tenant/workspace isolation scope (optional)
 *
 * Tokenable models gain the ability to:
 * - Create and manage multiple access tokens with different abilities
 * - Organize tokens into groups for logical separation
 * - Track the currently active token during a request
 * - Check permissions via the active token
 *
 * ```php
 * class User extends Model implements HasAccessTokens
 * {
 *     use HasAccessTokensTrait;
 *
 *     // Now users can create and manage tokens
 * }
 *
 * // Creating tokens
 * $token = $user->accessTokens()->create([...]);
 *
 * // Checking abilities
 * if ($user->accessTokenCan('posts:write')) {
 *     // User's current token has write permission
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface HasAccessTokens
{
    /**
     * Get all access tokens owned by this model.
     *
     * Returns a morph many relationship to the AccessToken model where this
     * model is the owner. The owner is the entity that created/owns the token.
     *
     * @return MorphMany<AccessToken, Model&self> Relationship to AccessToken models
     */
    public function accessTokens(): MorphMany;

    /**
     * Get all access tokens where this model is the context.
     *
     * Returns tokens that act on behalf of this model. The context represents
     * what entity the token operates within or for.
     *
     * @return MorphMany<AccessToken, Model&self> Relationship to AccessToken models
     */
    public function contextTokens(): MorphMany;

    /**
     * Get all access tokens scoped to this model as a boundary.
     *
     * Returns tokens that are isolated within this model's tenant scope.
     * The boundary provides multi-tenancy isolation.
     *
     * @return MorphMany<AccessToken, Model&self> Relationship to AccessToken models
     */
    public function boundaryTokens(): MorphMany;

    /**
     * Get all token groups that belong to this model.
     *
     * Returns a morph many relationship to the AccessTokenGroup model, enabling
     * logical organization of tokens into named groups (e.g., 'mobile-app',
     * 'integrations', 'admin-tools').
     *
     * @return MorphMany<AccessTokenGroup, Model&self> Relationship to AccessTokenGroup models
     */
    public function accessTokenGroups(): MorphMany;

    /**
     * Get the access token currently associated with this model.
     *
     * During an authenticated request, this returns the token that was used
     * to authenticate. Returns null if the model is not currently authenticated
     * via a token (e.g., session authentication) or outside of a request context.
     *
     * @return null|HasAbilities The current token instance, or null if not authenticated via token
     */
    public function currentAccessToken(): ?HasAbilities;

    /**
     * Set the current access token for this model.
     *
     * Associates a token instance with this model for the duration of the request.
     * This is typically called by authentication guards after successful token
     * validation.
     *
     * @param  HasAbilities $accessToken The authenticated token instance
     * @return static       Fluent interface for method chaining
     */
    public function withAccessToken(HasAbilities $accessToken): static;

    /**
     * Determine if the current token has a given ability.
     *
     * Convenience method that checks if the currently associated token (if any)
     * has the specified ability. Returns false if no token is currently associated.
     *
     * This provides a cleaner API than checking currentAccessToken() and can()
     * separately, especially in authorization logic.
     *
     * @param  string $ability The ability to check (e.g., 'users:read', 'posts:write')
     * @return bool   True if current token has this ability, false otherwise
     */
    public function accessTokenCan(string $ability): bool;
}
