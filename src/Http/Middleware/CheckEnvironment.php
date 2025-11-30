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
use Cline\Bearer\Exceptions\InvalidEnvironmentException;
use Closure;
use Illuminate\Http\Request;

use function in_array;
use function is_string;

/**
 * Middleware to ensure the current token is for a specific environment.
 *
 * This middleware validates that the authenticated user's current access token
 * matches one of the allowed environments (e.g., 'test', 'live', 'development').
 * This enables separation between production and test/development API access.
 *
 * Common use cases:
 * - Prevent test tokens from accessing production endpoints
 * - Restrict certain operations to live environment only
 * - Allow sandbox testing with test environment tokens
 *
 * Usage in routes:
 * ```php
 * Route::post('/payments/charge', function () {
 *     // Only live environment tokens can charge real payments
 * })->middleware('environment:live');
 *
 * Route::post('/sandbox/test', function () {
 *     // Only test environment tokens can access
 * })->middleware('environment:test');
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CheckEnvironment
{
    /**
     * Handle the incoming request.
     *
     * Verifies that:
     * 1. A user is authenticated
     * 2. The user has a current access token (not session-based auth)
     * 3. The token's environment matches one of the allowed environments
     *
     * @param Request                 $request         The incoming HTTP request
     * @param Closure(Request): mixed $next            The next middleware handler
     * @param string                  ...$environments Variable list of allowed environments
     *
     * @throws AuthenticationException     If no user or token is present
     * @throws InvalidEnvironmentException If the token environment doesn't match any allowed environment
     *
     * @return mixed The response from the next handler
     */
    public function handle(Request $request, Closure $next, string ...$environments): mixed
    {
        $user = $request->user();

        if (!$user instanceof HasApiTokens) {
            throw AuthenticationException::unauthenticated();
        }

        $currentToken = $user->currentAccessToken();

        if (!$currentToken instanceof HasAbilities) {
            throw AuthenticationException::unauthenticated();
        }

        /** @var mixed */
        $currentEnvironment = $currentToken->environment ?? null;

        if (!is_string($currentEnvironment)) {
            throw AuthenticationException::unauthenticated();
        }

        if (!in_array($currentEnvironment, $environments, true)) {
            throw InvalidEnvironmentException::notAllowed($currentEnvironment, $environments);
        }

        return $next($request);
    }
}
