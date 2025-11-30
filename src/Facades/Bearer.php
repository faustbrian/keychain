<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Facades;

use Cline\Bearer\BearerManager;
use Cline\Bearer\Conductors\TokenIssuanceConductor;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Contracts\TokenType;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\NewAccessToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Facade;

/**
 * Laravel facade for Bearer token authentication manager.
 *
 * Provides static access to the BearerManager for managing personal access tokens,
 * token types, hashers, rotation strategies, and audit logging. This facade simplifies
 * token operations throughout your application.
 *
 * ```php
 * // Issue a new token
 * $token = Bearer::for($user)->create('Mobile App', ['posts:read']);
 *
 * // Find and validate tokens
 * $accessToken = Bearer::findToken($token);
 *
 * // Revoke tokens
 * Bearer::revoke($accessToken);
 * ```
 *
 * @method static Authenticatable        actingAs(Authenticatable $user, array<int, string> $abilities = [], ?string $type = null, string $guard = 'bearer')
 * @method static AuditDriver            auditDriver(?string $name = null)
 * @method static void                   authenticateAccessTokensUsing(?\Closure $callback)
 * @method static AccessToken|null       findByPrefix(string $prefix)
 * @method static AccessToken|null       findToken(string $token)
 * @method static TokenIssuanceConductor for(Model $tokenable)
 * @method static void                   getAccessTokenFromRequestUsing(?\Closure $callback)
 * @method static string                 personalAccessTokenModel()
 * @method static void                   registerAuditDriver(string $name, AuditDriver $driver)
 * @method static void                   registerRevocationStrategy(string $name, RevocationStrategy $strategy)
 * @method static void                   registerRotationStrategy(string $name, RotationStrategy $strategy)
 * @method static void                   registerTokenGenerator(string $name, TokenGenerator $generator)
 * @method static void                   registerTokenHasher(string $name, TokenHasher $hasher)
 * @method static void                   registerTokenType(string $key, TokenType $type)
 * @method static RevocationStrategy     revocationStrategy(?string $name = null)
 * @method static void                   revoke(AccessToken $token, ?string $strategy = null)
 * @method static NewAccessToken         rotate(AccessToken $token, ?string $strategy = null)
 * @method static RotationStrategy       rotationStrategy(?string $name = null)
 * @method static TokenGenerator         tokenGenerator(?string $name = null)
 * @method static string                 tokenGroupModel()
 * @method static TokenHasher            tokenHasher(?string $name = null)
 * @method static TokenType              tokenType(string $type)
 * @method static void                   useAccessTokenGroupModel(string $model)
 * @method static void                   useAccessTokenModel(string $model)
 *
 * @see BearerManager
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Bearer extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * Returns the service container binding for the BearerManager instance
     * that this facade proxies to.
     *
     * @return string The fully qualified class name of BearerManager
     */
    protected static function getFacadeAccessor(): string
    {
        return BearerManager::class;
    }
}
