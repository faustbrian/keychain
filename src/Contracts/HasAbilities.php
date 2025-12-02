<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

/**
 * Contract for objects that can check token abilities/permissions.
 *
 * This contract defines the ability-checking interface for access tokens, enabling
 * fine-grained permission control beyond simple authentication. Tokens can be
 * scoped to specific abilities, restricting what actions they can perform.
 *
 * Common use cases include:
 * - Read-only tokens that can only fetch data but not modify it
 * - Service tokens with specific operational permissions
 * - User tokens with role-based abilities
 * - Temporary tokens with limited scopes
 *
 * ```php
 * // Check if token has specific ability
 * if ($token->can('users:write')) {
 *     // Perform write operation
 * }
 *
 * // Verify token lacks an ability
 * if ($token->cant('admin:delete')) {
 *     abort(403, 'Insufficient permissions');
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface HasAbilities
{
    /**
     * Determine if the token has a given ability.
     *
     * Checks whether the token possesses the specified ability/permission.
     * Ability names are typically namespaced (e.g., 'users:read', 'posts:write')
     * but the format is flexible and determined by your application's needs.
     *
     * Wildcard abilities (e.g., '*') typically grant all permissions, but this
     * behavior depends on the implementation.
     *
     * @param  string $ability The ability to check (e.g., 'users:read', 'posts:write')
     * @return bool   True if the token has this ability, false otherwise
     */
    public function can(string $ability): bool;

    /**
     * Determine if the token is missing a given ability.
     *
     * Inverse of can(). Provides a more expressive API for checking the absence
     * of permissions, which can make authorization logic more readable.
     *
     * @param  string $ability The ability to check for absence
     * @return bool   True if the token lacks this ability, false if it has it
     */
    public function cant(string $ability): bool;
}
