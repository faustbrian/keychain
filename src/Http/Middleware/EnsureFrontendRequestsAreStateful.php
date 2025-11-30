<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Http\Middleware;

use Cline\Bearer\Exceptions\InvalidStatefulDomainException;
use Closure;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Http\Request;
use Illuminate\Routing\Pipeline;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

use function app;
use function array_filter;
use function array_unique;
use function array_unshift;
use function array_values;
use function config;
use function is_string;
use function mb_trim;

/**
 * Middleware to configure stateful authentication for first-party frontends.
 *
 * This middleware enables session-based authentication for requests from
 * trusted frontend applications (SPAs, mobile apps, etc.), while maintaining
 * token-based authentication for third-party API consumers.
 *
 * When a request originates from a configured stateful domain:
 * - Session cookies are encrypted and HTTP-only
 * - CSRF protection is enabled
 * - Standard Laravel session middleware is applied
 * - The request is marked as coming from a trusted frontend
 *
 * This provides the security benefits of session authentication for your own
 * applications while still supporting token authentication for external API access.
 *
 * Configuration:
 * ```php
 * // config/bearer.php
 * 'stateful' => [
 *     'localhost',
 *     'localhost:3000',
 *     'app.example.com',
 * ],
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class EnsureFrontendRequestsAreStateful
{
    /**
     * Determine if the request is from a first-party application frontend.
     *
     * Checks if the request's origin or referer header matches one of the
     * configured stateful domains in the bearer.stateful config array.
     *
     * @param  Request $request The incoming HTTP request
     * @return bool    True if from a configured frontend domain, false otherwise
     */
    public static function fromFrontend(Request $request): bool
    {
        $domain = $request->headers->get('referer') ?: $request->headers->get('origin');

        if ($domain === null) {
            return false;
        }

        // Normalize domain by removing protocol and ensuring trailing slash
        $domain = Str::replaceFirst('https://', '', $domain);
        $domain = Str::replaceFirst('http://', '', $domain);
        $domain = Str::endsWith($domain, '/') ? $domain : $domain.'/';

        /** @var array<array-key, mixed> $statefulConfig */
        $statefulConfig = config('bearer.stateful', []);
        $stateful = array_filter($statefulConfig);

        return Str::is(Collection::make($stateful)->map(function (mixed $uri) use ($request): string {
            // Support placeholder for current request host
            if ($uri === '*') {
                return mb_trim($request->getHttpHost()).'/*';
            }

            if (!is_string($uri)) {
                throw InvalidStatefulDomainException::mustBeString();
            }

            return mb_trim($uri).'/*';
        })->all(), $domain);
    }

    /**
     * Handle the incoming request.
     *
     * Configures secure cookie sessions and conditionally applies frontend
     * middleware stack based on the request origin.
     *
     * @param  Request                 $request The incoming HTTP request
     * @param  Closure(Request): mixed $next    The next middleware handler
     * @return mixed                   The response from the middleware pipeline
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $this->configureSecureCookieSessions();

        return new Pipeline(app())->send($request)->through(
            self::fromFrontend($request) ? $this->frontendMiddleware() : [],
        )->then(fn (Request $request): mixed => $next($request));
    }

    /**
     * Configure secure cookie sessions.
     *
     * Ensures session cookies are HTTP-only and use SameSite for
     * CSRF protection. Values are configurable via bearer.session config.
     */
    private function configureSecureCookieSessions(): void
    {
        config([
            'session.http_only' => config('bearer.session.http_only', true),
            'session.same_site' => config('bearer.session.same_site', 'lax'),
        ]);
    }

    /**
     * Get the middleware that should be applied to frontend requests.
     *
     * Returns the standard Laravel session and CSRF middleware stack,
     * configured via the bearer.middleware config settings.
     *
     * @return array<int, (callable(Request, Closure): mixed)|class-string> Middleware stack for frontend requests
     */
    private function frontendMiddleware(): array
    {
        /** @var array<int, null|class-string> $configuredMiddleware */
        $configuredMiddleware = [
            config('bearer.middleware.encrypt_cookies', EncryptCookies::class),
            config('bearer.middleware.add_queued_cookies', AddQueuedCookiesToResponse::class),
            config('bearer.middleware.start_session', StartSession::class),
            config('bearer.middleware.validate_csrf_token', config('bearer.middleware.verify_csrf_token', VerifyCsrfToken::class)),
            config('bearer.middleware.authenticate_session'),
        ];

        /** @var array<int, class-string> $middleware */
        $middleware = array_values(array_filter(array_unique($configuredMiddleware)));

        // Mark request as coming from a trusted frontend
        array_unshift($middleware, function (Request $request, Closure $next): mixed {
            $request->attributes->set('bearer', true);

            return $next($request);
        });

        return $middleware;
    }
}
