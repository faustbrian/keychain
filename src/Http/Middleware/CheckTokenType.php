<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Http\Middleware;

use Cline\Bearer\Exceptions\AuthenticationException;
use Cline\Bearer\Exceptions\InvalidTokenTypeException;
use Closure;
use Illuminate\Http\Request;

use function in_array;
use function is_object;
use function method_exists;

/**
 * Middleware to ensure the current token is one of the specified types.
 *
 * This middleware validates that the authenticated user's current access token
 * matches one of the allowed token types (e.g., 'sk', 'pk', 'rk'). This is useful
 * for restricting endpoints to specific token categories.
 *
 * For example, you might want certain endpoints to only accept secret keys (sk)
 * and not publishable keys (pk), or restrict admin operations to restricted keys (rk).
 *
 * Usage in routes:
 * ```php
 * Route::post('/webhooks', function () {
 *     // Only secret keys can configure webhooks
 * })->middleware('token-type:sk');
 *
 * Route::get('/public-config', function () {
 *     // Both publishable and secret keys can access
 * })->middleware('token-type:pk,sk');
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CheckTokenType
{
    /**
     * Handle the incoming request.
     *
     * Verifies that:
     * 1. A user is authenticated
     * 2. The user has a current access token (not session-based auth)
     * 3. The token's type matches one of the allowed types
     *
     * @param Request                 $request  The incoming HTTP request
     * @param Closure(Request): mixed $next     The next middleware handler
     * @param string                  ...$types Variable list of allowed token types
     *
     * @throws AuthenticationException   If no user or token is present
     * @throws InvalidTokenTypeException If the token type doesn't match any allowed type
     *
     * @return mixed The response from the next handler
     */
    public function handle(Request $request, Closure $next, string ...$types): mixed
    {
        $user = $request->user();

        if (!is_object($user) || !method_exists($user, 'currentAccessToken')) {
            throw AuthenticationException::unauthenticated();
        }

        /** @var null|object{type: string} $currentToken */
        $currentToken = $user->currentAccessToken();

        if (!$currentToken) {
            throw AuthenticationException::unauthenticated();
        }

        $currentType = $currentToken->type;

        if (!in_array($currentType, $types, true)) {
            throw InvalidTokenTypeException::notAllowedForRequest($currentType, $types);
        }

        return $next($request);
    }
}
