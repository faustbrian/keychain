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

/**
 * Static configuration for Keychain.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class KeychainConfig
{
    /**
     * The personal access token model class name.
     *
     * @var class-string<PersonalAccessToken>
     */
    public static string $personalAccessTokenModel = PersonalAccessToken::class;

    /**
     * The token group model class name.
     *
     * @var class-string
     */
    public static string $tokenGroupModel = TokenGroup::class;

    /**
     * A callback that can retrieve the access token from the request.
     */
    public static ?Closure $accessTokenRetrievalCallback = null;

    /**
     * A callback that can add to the validation of the access token.
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
     * Specify a callback that should be used to fetch the access token from the request.
     */
    public static function getAccessTokenFromRequestUsing(?Closure $callback): void
    {
        self::$accessTokenRetrievalCallback = $callback;
    }

    /**
     * Specify a callback that should be used to authenticate access tokens.
     */
    public static function authenticateAccessTokensUsing(?Closure $callback): void
    {
        self::$accessTokenAuthenticationCallback = $callback;
    }
}
