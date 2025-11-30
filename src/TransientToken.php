<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer;

use Cline\Bearer\Contracts\HasAbilities;

/**
 * An in-memory token that grants all abilities without database persistence.
 *
 * This token implementation is used for testing and for session-based authentication
 * where the user is authenticated via traditional Laravel session guards (e.g., 'web')
 * rather than API tokens.
 *
 * When a user authenticates via a session, they are given a TransientToken which:
 * - Always returns true for can() checks (has all abilities)
 * - Always returns false for cant() checks (lacks no abilities)
 * - Exists only in memory for the request lifetime
 * - Is never persisted to the database
 *
 * This provides a consistent HasAbilities interface whether authentication is
 * via session or token, simplifying authorization logic throughout the application.
 *
 * Example usage:
 * ```php
 * // In guard when session user is found
 * $user->withAccessToken(new TransientToken());
 *
 * // Later in authorization checks
 * if ($user->tokenCan('any:ability')) {
 *     // Always true for TransientToken
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TransientToken implements HasAbilities
{
    /**
     * Determine if the token has a given ability.
     *
     * TransientTokens always have all abilities, making them suitable for
     * session-based authentication where traditional Laravel authorization
     * (gates, policies) handles permission checks instead of token abilities.
     *
     * @param  string $ability The ability to check (ignored for transient tokens)
     * @return bool   Always returns true
     */
    public function can(string $ability): bool
    {
        return true;
    }

    /**
     * Determine if the token is missing a given ability.
     *
     * TransientTokens are never missing any abilities, as they represent
     * fully authenticated session users without token-based restrictions.
     *
     * @param  string $ability The ability to check (ignored for transient tokens)
     * @return bool   Always returns false
     */
    public function cant(string $ability): bool
    {
        return false;
    }
}
