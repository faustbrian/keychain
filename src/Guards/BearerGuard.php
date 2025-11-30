<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Guards;

use Cline\Bearer\BearerManager;
use Cline\Bearer\Concerns\HasApiTokens;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Events\TokenAuthenticated;
use Cline\Bearer\Exceptions\DomainRestrictionException;
use Cline\Bearer\Exceptions\IpRestrictionException;
use Cline\Bearer\Exceptions\TokenExpiredException;
use Cline\Bearer\Exceptions\TokenRevokedException;
use Cline\Bearer\TransientToken;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;

use const PHP_URL_HOST;

use function assert;
use function class_uses_recursive;
use function config;
use function event;
use function in_array;
use function is_object;
use function is_string;
use function now;
use function parse_url;
use function sprintf;

/**
 * Authentication guard for Bearer token-based authentication.
 *
 * This guard handles authentication via personal access tokens, providing:
 * - Stateful session authentication fallback for web requests
 * - Bearer token validation and parsing
 * - Token expiration and revocation checks
 * - IP and domain restriction enforcement
 * - Automatic last_used_at tracking
 * - Authentication event dispatching
 *
 * The guard follows a two-step authentication flow:
 * 1. First check stateful guards (web sessions) for authenticated users
 * 2. If no session user, validate bearer token from request headers
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class BearerGuard
{
    /**
     * Create a new guard instance.
     *
     * @param AuthFactory   $auth       The authentication factory for checking stateful guards
     * @param BearerManager $bearer     The bearer manager for token operations
     * @param null|int      $expiration Optional token expiration in minutes
     * @param null|string   $provider   Optional auth provider name to validate tokenable type
     */
    public function __construct(
        private AuthFactory $auth,
        private BearerManager $bearer,
        private ?int $expiration = null,
        private ?string $provider = null,
    ) {}

    /**
     * Retrieve the authenticated user for the incoming request.
     *
     * Attempts authentication via:
     * 1. Stateful guards (web sessions) - users get TransientToken with all abilities
     * 2. Bearer token validation - validates token and enforces restrictions
     *
     * @param  Request $request The incoming HTTP request
     * @return mixed   The authenticated tokenable user, or null if authentication fails
     */
    public function __invoke(Request $request): mixed
    {
        // Check stateful guards first (web sessions)
        foreach (Arr::wrap(config('bearer.guard', 'web')) as $guard) {
            assert(is_string($guard));

            if ($user = $this->auth->guard($guard)->user()) {
                if ($this->supportsTokens($user)) {
                    assert($user instanceof \Cline\Bearer\Contracts\HasApiTokens);

                    return $user->withAccessToken(
                        new TransientToken(),
                    );
                }

                return $user;
            }
        }

        // Get token from request (Bearer token)
        $token = $this->getTokenFromRequest($request);

        if ($token === null) {
            return null;
        }

        // Find token by hash
        $accessToken = $this->bearer->findToken($token);

        if (!$this->isValidAccessToken($accessToken)) {
            return null;
        }

        assert($accessToken instanceof AccessToken);

        if (!$this->supportsTokens($accessToken->tokenable)) {
            return null;
        }

        // Validate IP restrictions
        try {
            $this->validateIpRestrictions($accessToken, $request);
        } catch (IpRestrictionException) {
            return null;
        }

        // Validate domain restrictions
        try {
            $this->validateDomainRestrictions($accessToken, $request);
        } catch (DomainRestrictionException) {
            return null;
        }

        assert($accessToken->tokenable instanceof \Cline\Bearer\Contracts\HasApiTokens);

        // Attach token to tokenable
        $tokenable = $accessToken->tokenable->withAccessToken($accessToken);

        // Dispatch authentication event
        event(
            new TokenAuthenticated(
                $accessToken,
                $request->ip(),
                $request->userAgent(),
            ),
        );

        // Update last_used_at
        $this->updateLastUsedAt($accessToken);

        return $tokenable;
    }

    /**
     * Get the token from the request.
     *
     * Extracts the bearer token from the Authorization header.
     *
     * @param  Request     $request The incoming HTTP request
     * @return null|string The extracted token, or null if not present
     */
    private function getTokenFromRequest(Request $request): ?string
    {
        return $request->bearerToken();
    }

    /**
     * Determine if the provided access token is valid.
     *
     * Validates:
     * - Token exists
     * - Token is not expired (both expiration and created_at checks)
     * - Token is not revoked
     * - Tokenable matches configured provider (if specified)
     *
     * @param  null|AccessToken $token The token to validate
     * @return bool             True if valid, false otherwise
     */
    private function isValidAccessToken(?AccessToken $token): bool
    {
        if (!$token instanceof AccessToken) {
            return false;
        }

        // Check if token is revoked
        if ($token->revoked_at !== null) {
            throw TokenRevokedException::revoked();
        }

        // Check expiration via created_at + expiration minutes
        if ($this->expiration !== null && $token->created_at->lt(now()->subMinutes($this->expiration))) {
            throw TokenExpiredException::expired();
        }

        // Check explicit expires_at timestamp
        if ($token->expires_at !== null && $token->expires_at->isPast()) {
            throw TokenExpiredException::expired();
        }

        // Validate provider
        return $this->hasValidProvider($token->tokenable);
    }

    /**
     * Validate IP address restrictions.
     *
     * If the token has IP restrictions, ensures the request IP is in the allowlist.
     *
     * @param AccessToken $token   The token to validate
     * @param Request     $request The incoming request
     *
     * @throws IpRestrictionException If IP is not allowed
     */
    private function validateIpRestrictions(AccessToken $token, Request $request): void
    {
        if ($token->allowed_ips === null || $token->allowed_ips === []) {
            return;
        }

        $requestIp = $request->ip();
        assert(is_string($requestIp));

        if (!in_array($requestIp, $token->allowed_ips, true)) {
            throw IpRestrictionException::forIp($requestIp);
        }
    }

    /**
     * Validate domain restrictions.
     *
     * If the token has domain restrictions, ensures the request origin/referer
     * matches one of the allowed domains.
     *
     * @param AccessToken $token   The token to validate
     * @param Request     $request The incoming request
     *
     * @throws DomainRestrictionException If domain is not allowed
     */
    private function validateDomainRestrictions(AccessToken $token, Request $request): void
    {
        if ($token->allowed_domains === null || $token->allowed_domains === []) {
            return;
        }

        $domain = $request->headers->get('origin') ?? $request->headers->get('referer');

        if ($domain === null) {
            throw DomainRestrictionException::missingHeader();
        }

        // Extract domain from URL
        $parsedDomain = parse_url($domain, PHP_URL_HOST);

        if ($parsedDomain === false || $parsedDomain === null) {
            throw DomainRestrictionException::missingHeader();
        }

        if (!in_array($parsedDomain, $token->allowed_domains, true)) {
            throw DomainRestrictionException::forDomain($parsedDomain);
        }
    }

    /**
     * Determine if the tokenable model supports API tokens.
     *
     * Checks if the tokenable model uses the HasApiTokens contract.
     *
     * @param  mixed $tokenable The model to check
     * @return bool  True if model supports tokens, false otherwise
     */
    private function supportsTokens(mixed $tokenable = null): bool
    {
        if ($tokenable === null) {
            return false;
        }

        if (!is_object($tokenable)) {
            return false;
        }

        return in_array(HasApiTokens::class, class_uses_recursive($tokenable::class), true);
    }

    /**
     * Determine if the tokenable model matches the provider's model type.
     *
     * If a provider is configured, validates that the tokenable is an instance
     * of the provider's configured model class.
     *
     * @param  mixed $tokenable The tokenable model to validate
     * @return bool  True if provider is valid or not configured, false otherwise
     */
    private function hasValidProvider(mixed $tokenable): bool
    {
        if ($this->provider === null) {
            return true;
        }

        $model = config(sprintf('auth.providers.%s.model', $this->provider));

        if (!is_string($model)) {
            return false;
        }

        return $tokenable instanceof $model;
    }

    /**
     * Store the time the token was last used.
     *
     * Updates the last_used_at timestamp while preserving the database
     * modification state for other operations in the request lifecycle.
     *
     * @param AccessToken $accessToken The token to update
     */
    private function updateLastUsedAt(AccessToken $accessToken): void
    {
        $connection = $accessToken->getConnection();

        // Only preserve modification state if connection supports it
        if ($connection instanceof Connection) {
            $hasModifiedRecords = $connection->hasModifiedRecords();
            $accessToken->forceFill(['last_used_at' => now()])->save();
            $connection->setRecordModificationState($hasModifiedRecords);
        } else {
            $accessToken->forceFill(['last_used_at' => now()])->save();
        }
    }
}
