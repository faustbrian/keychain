<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Facades;

use Cline\Keychain\Conductors\TokenIssuanceConductor;
use Cline\Keychain\Contracts\AuditDriver;
use Cline\Keychain\Contracts\RevocationStrategy;
use Cline\Keychain\Contracts\RotationStrategy;
use Cline\Keychain\Contracts\TokenGenerator;
use Cline\Keychain\Contracts\TokenHasher;
use Cline\Keychain\Contracts\TokenType;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\KeychainManager;
use Cline\Keychain\NewAccessToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Facade;

/**
 * Laravel facade for Keychain manager.
 *
 * @method static Authenticatable          actingAs(Authenticatable $user, array<int, string> $abilities = [], ?string $type = null, string $guard = 'keychain')
 * @method static AuditDriver              auditDriver(?string $name = null)
 * @method static void                     authenticateAccessTokensUsing(?\Closure $callback)
 * @method static PersonalAccessToken|null findByPrefix(string $prefix)
 * @method static PersonalAccessToken|null findToken(string $token)
 * @method static TokenIssuanceConductor   for(Model $tokenable)
 * @method static void                     getAccessTokenFromRequestUsing(?\Closure $callback)
 * @method static string                   personalAccessTokenModel()
 * @method static void                     registerAuditDriver(string $name, AuditDriver $driver)
 * @method static void                     registerRevocationStrategy(string $name, RevocationStrategy $strategy)
 * @method static void                     registerRotationStrategy(string $name, RotationStrategy $strategy)
 * @method static void                     registerTokenGenerator(string $name, TokenGenerator $generator)
 * @method static void                     registerTokenHasher(string $name, TokenHasher $hasher)
 * @method static void                     registerTokenType(string $key, TokenType $type)
 * @method static RevocationStrategy       revocationStrategy(?string $name = null)
 * @method static void                     revoke(PersonalAccessToken $token, ?string $strategy = null)
 * @method static NewAccessToken           rotate(PersonalAccessToken $token, ?string $strategy = null)
 * @method static RotationStrategy         rotationStrategy(?string $name = null)
 * @method static TokenGenerator           tokenGenerator(?string $name = null)
 * @method static string                   tokenGroupModel()
 * @method static TokenHasher              tokenHasher(?string $name = null)
 * @method static TokenType                tokenType(string $type)
 * @method static void                     usePersonalAccessTokenModel(string $model)
 * @method static void                     useTokenGroupModel(string $model)
 *
 * @see KeychainManager
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Keychain extends Facade
{
    /**
     * Get the registered name of the component.
     */
    protected static function getFacadeAccessor(): string
    {
        return KeychainManager::class;
    }
}
