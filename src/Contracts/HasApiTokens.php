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
 * Contract for models that can own API tokens.
 *
 * This contract defines the interface for tokenable models (typically User models)
 * that can create, manage, and authenticate via personal access tokens. It provides
 * the foundation for token-based authentication in your application.
 *
 * Tokenable models gain the ability to:
 * - Create and manage multiple API tokens with different abilities
 * - Organize tokens into groups for logical separation
 * - Track the currently active token during a request
 * - Check permissions via the active token
 *
 * ```php
 * class User extends Model implements HasApiTokens
 * {
 *     use HasApiTokensTrait;
 *
 *     // Now users can create and manage tokens
 * }
 *
 * // Creating tokens
 * $token = $user->tokens()->create([...]);
 *
 * // Checking abilities
 * if ($user->tokenCan('posts:write')) {
 *     // User's current token has write permission
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface HasApiTokens
{
    /**
     * Get all access tokens that belong to this model.
     *
     * Returns a morph many relationship to the AccessToken model,
     * allowing you to query, create, update, and delete tokens associated
     * with this tokenable entity.
     *
     * @return MorphMany<AccessToken, Model&self> Relationship to AccessToken models
     */
    public function tokens(): MorphMany;

    /**
     * Get all token groups that belong to this model.
     *
     * Returns a morph many relationship to the AccessTokenGroup model, enabling
     * logical organization of tokens into named groups (e.g., 'mobile-app',
     * 'integrations', 'admin-tools').
     *
     * @return MorphMany<AccessTokenGroup, Model&self> Relationship to AccessTokenGroup models
     */
    public function tokenGroups(): MorphMany;

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
    public function tokenCan(string $ability): bool;
}
