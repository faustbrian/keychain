<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Http\Middleware;

use Cline\Bearer\Contracts\HasAbilities;
use Cline\Bearer\Contracts\HasApiTokens;
use Cline\Bearer\Exceptions\AuthenticationException;
use Cline\Bearer\Exceptions\MissingAbilityException;
use Closure;
use Illuminate\Http\Request;

/**
 * Middleware to ensure the current token has ALL specified abilities.
 *
 * This middleware validates that the authenticated user's current access token
 * possesses every ability listed in the middleware parameters. If any ability
 * is missing, a MissingAbilityException is thrown.
 *
 * Use this when an endpoint requires multiple permissions simultaneously.
 *
 * Usage in routes:
 * ```php
 * Route::post('/admin/users', function () {
 *     // Only tokens with both 'users:write' AND 'admin:access'
 * })->middleware('abilities:users:write,admin:access');
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CheckAbilities
{
    /**
     * Handle the incoming request.
     *
     * Verifies that:
     * 1. A user is authenticated
     * 2. The user has a current access token (not session-based auth)
     * 3. The token has ALL specified abilities
     *
     * @param Request                 $request      The incoming HTTP request
     * @param Closure(Request): mixed $next         The next middleware handler
     * @param string                  ...$abilities Variable list of required abilities
     *
     * @throws AuthenticationException If no user or token is present
     * @throws MissingAbilityException If the token lacks any required ability
     *
     * @return mixed The response from the next handler
     */
    public function handle(Request $request, Closure $next, string ...$abilities): mixed
    {
        $user = $request->user();

        if (!$user instanceof HasApiTokens || !$user->currentAccessToken() instanceof HasAbilities) {
            throw AuthenticationException::unauthenticated();
        }

        foreach ($abilities as $ability) {
            if (!$user->tokenCan($ability)) {
                throw MissingAbilityException::missing($ability);
            }
        }

        return $next($request);
    }
}
