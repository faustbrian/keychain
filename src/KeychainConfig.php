<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain;

use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Database\Models\TokenGroup;
use Closure;
use Illuminate\Http\Request;

/**
 * Static configuration for Keychain package.
 *
 * Provides centralized configuration for model class names and callback customization.
 * Allows applications to use custom model implementations and authentication logic
 * through a static API that can be modified at runtime.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class KeychainConfig
{
    /**
     * The personal access token model class name.
     *
     * Defines which Eloquent model class should be used for personal access tokens.
     * Applications can override this to use custom model implementations with
     * additional fields, relationships, or business logic.
     *
     * @var class-string<PersonalAccessToken>
     */
    public static string $personalAccessTokenModel = PersonalAccessToken::class;

    /**
     * The token group model class name.
     *
     * Defines which Eloquent model class should be used for token groups.
     * Applications can override this to use custom model implementations for
     * organizing related tokens into logical groupings.
     *
     * @var class-string
     */
    public static string $tokenGroupModel = TokenGroup::class;

    /**
     * Custom callback for retrieving access tokens from requests.
     *
     * Allows applications to implement custom token extraction logic from incoming
     * HTTP requests. When set, this callback is invoked instead of the default
     * bearer token extraction mechanism.
     *
     * @var null|(Closure(Request): (null|string))
     */
    public static ?Closure $accessTokenRetrievalCallback = null;

    /**
     * Custom callback for additional access token validation.
     *
     * Allows applications to implement custom authentication logic beyond the
     * default token verification. This callback can enforce additional security
     * constraints like IP whitelisting, rate limiting, or context-based validation.
     *
     * @var null|Closure(PersonalAccessToken, Request): bool
     */
    public static ?Closure $accessTokenAuthenticationCallback = null;

    /**
     * Get the personal access token model class name.
     *
     * @return class-string<PersonalAccessToken>
     */
    public static function personalAccessTokenModel(): string
    {
        return self::$personalAccessTokenModel;
    }

    /**
     * Set the personal access token model class name.
     *
     * @param class-string<PersonalAccessToken> $model
     */
    public static function usePersonalAccessTokenModel(string $model): void
    {
        self::$personalAccessTokenModel = $model;
    }

    /**
     * Get the token group model class name.
     *
     * @return class-string
     */
    public static function tokenGroupModel(): string
    {
        return self::$tokenGroupModel;
    }

    /**
     * Set the token group model class name.
     *
     * @param class-string $model
     */
    public static function useTokenGroupModel(string $model): void
    {
        self::$tokenGroupModel = $model;
    }

    /**
     * Set the callback for custom token retrieval from requests.
     *
     * Registers a custom callback that will be used to extract access tokens from
     * incoming HTTP requests. This allows applications to implement non-standard
     * token extraction logic (e.g., from custom headers, cookies, or query parameters).
     *
     * @param null|(Closure(Request): (null|string)) $callback The token retrieval callback or null to reset
     */
    public static function getAccessTokenFromRequestUsing(?Closure $callback): void
    {
        self::$accessTokenRetrievalCallback = $callback;
    }

    /**
     * Set the callback for custom token authentication.
     *
     * Registers a custom callback that will be invoked during token authentication
     * to perform additional validation beyond the standard token verification. This
     * enables custom security policies like IP restrictions, environment checks,
     * or contextual authorization.
     *
     * @param null|Closure(PersonalAccessToken, Request): bool $callback The authentication callback or null to reset
     */
    public static function authenticateAccessTokensUsing(?Closure $callback): void
    {
        self::$accessTokenAuthenticationCallback = $callback;
    }
}
