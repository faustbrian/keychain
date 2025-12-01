<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer;

use Cline\Bearer\AuditDrivers\AuditDriverRegistry;
use Cline\Bearer\Conductors\TokenDerivationConductor;
use Cline\Bearer\Conductors\TokenIssuanceConductor;
use Cline\Bearer\Conductors\TokenRevocationConductor;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Contracts\HasAccessTokens;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Contracts\TokenType;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\RevocationStrategies\RevocationStrategyRegistry;
use Cline\Bearer\RotationStrategies\RotationStrategyRegistry;
use Cline\Bearer\Testing\TestingToken;
use Cline\Bearer\TokenGenerators\TokenGeneratorRegistry;
use Cline\Bearer\TokenHashers\TokenHasherRegistry;
use Cline\Bearer\TokenTypes\TokenTypeRegistry;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Throwable;

use function config;
use function explode;
use function property_exists;
use function str_contains;

/**
 * Central manager for personal access token operations.
 *
 * Manages token types, generators, audit drivers, and provides the main
 * API for token issuance, retrieval, revocation, and rotation operations.
 * Uses dependency injection for registries and container access.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class BearerManager
{
    /**
     * Create a new bearer manager instance.
     *
     * @param TokenTypeRegistry          $tokenTypes           Registry of token type implementations
     * @param TokenGeneratorRegistry     $tokenGenerators      Registry of token generator implementations
     * @param TokenHasherRegistry        $tokenHashers         Registry of token hasher implementations
     * @param AuditDriverRegistry        $auditDrivers         Registry of audit driver implementations
     * @param RevocationStrategyRegistry $revocationStrategies Registry of revocation strategy implementations
     * @param RotationStrategyRegistry   $rotationStrategies   Registry of rotation strategy implementations
     */
    public function __construct(
        private TokenTypeRegistry $tokenTypes,
        private TokenGeneratorRegistry $tokenGenerators,
        private TokenHasherRegistry $tokenHashers,
        private AuditDriverRegistry $auditDrivers,
        private RevocationStrategyRegistry $revocationStrategies,
        private RotationStrategyRegistry $rotationStrategies,
    ) {}

    /**
     * Create a token issuance conductor for the given owner model.
     *
     * Provides a fluent interface for configuring and issuing new tokens for an
     * owner entity (typically a User model). The conductor allows chaining
     * methods to set abilities, restrictions, metadata, context, boundary, and
     * other token properties before issuing the final token.
     *
     * @param  HasAccessTokens&Model  $owner The model that will own the issued token
     * @return TokenIssuanceConductor Fluent conductor for token configuration
     */
    public function for(Model $owner): TokenIssuanceConductor
    {
        return new TokenIssuanceConductor($this, $owner);
    }

    /**
     * Create a token revocation conductor for the given token.
     *
     * Provides a fluent interface for configuring and executing token revocation
     * operations. Allows selection of different revocation strategies (none, cascade,
     * partial, timed) and attachment of metadata describing the revocation reason.
     *
     * @param  AccessToken              $token The token to revoke
     * @return TokenRevocationConductor Fluent conductor for revocation configuration
     */
    public function revoke(AccessToken $token): TokenRevocationConductor
    {
        return new TokenRevocationConductor($this, $token);
    }

    /**
     * Create a token derivation conductor for the given parent token.
     *
     * Provides a fluent interface for deriving child tokens from a parent token.
     * Child tokens inherit restrictions from their parent and can have further
     * limited abilities. This enables hierarchical token relationships like
     * master tokens deriving customer-specific tokens.
     *
     * @param  AccessToken              $parentToken The parent token from which to derive
     * @return TokenDerivationConductor Fluent conductor for derivation configuration
     */
    public function derive(AccessToken $parentToken): TokenDerivationConductor
    {
        return new TokenDerivationConductor($this, $parentToken);
    }

    /**
     * Find a personal access token by its plain-text token string.
     *
     * Supports two token formats:
     * - Direct hash lookup: plain token without '|' separator
     * - ID-prefixed format: "{id}|{plain_token}" for faster database lookups
     *
     * @param  string           $token The plain-text token string to find
     * @return null|AccessToken The matched token or null if not found
     */
    public function findAccessToken(string $token): ?AccessToken
    {
        $hasher = $this->tokenHasher();

        // Tokens without | prefix are looked up by hash directly
        if (!str_contains($token, '|')) {
            /** @var null|AccessToken */
            return AccessToken::query()
                ->where('token', $hasher->hash($token))
                ->first();
        }

        // Tokens with id|plaintext format use id lookup + hash verification
        [$id, $plainToken] = explode('|', $token, 2);

        $instance = AccessToken::query()->find($id);

        if ($instance instanceof AccessToken && $hasher->verify($plainToken, $instance->token)) {
            return $instance;
        }

        return null;
    }

    /**
     * Find a personal access token by its prefix.
     *
     * Looks up a token by its unique prefix identifier. This is useful for
     * identifying token types or implementing prefix-based access controls.
     *
     * @param  string           $prefix The token prefix to search for
     * @return null|AccessToken The matched token or null if not found
     */
    public function findByPrefix(string $prefix): ?AccessToken
    {
        /** @var null|AccessToken */
        return AccessToken::query()
            ->where('prefix', $prefix)
            ->first();
    }

    /**
     * Execute token revocation with a specific strategy.
     *
     * Internal method that performs the actual revocation using the specified
     * or default strategy. Logs the revocation event to the configured audit
     * driver, but silently ignores audit failures to ensure revocation completes.
     *
     * @internal Use revoke() conductor pattern instead for public API
     *
     * @param AccessToken $token    The token to revoke
     * @param null|string $strategy Strategy name (null uses default from config)
     */
    public function executeRevocation(AccessToken $token, ?string $strategy = null): void
    {
        /** @var string $strategyName */
        $strategyName = $strategy ?? config('bearer.revocation.default', 'none');
        $revocationStrategy = $this->revocationStrategy($strategyName);

        $revocationStrategy->revoke($token);

        // Log audit event (failures should not affect revocation)
        try {
            $this->auditDriver()->log($token, AuditEvent::Revoked, [
                'strategy' => $strategyName,
            ]);
        } catch (Throwable) {
            // Silently ignore audit failures - revocation already completed
        }
    }

    /**
     * Rotate a personal access token using the specified strategy.
     *
     * Creates a new token with identical configuration to the original token,
     * then applies the specified rotation strategy to handle the old token
     * (e.g., immediate invalidation, grace period, or dual validity).
     * Preserves all settings including abilities, restrictions, metadata, and
     * group membership.
     *
     * @param  AccessToken    $token    The token to rotate
     * @param  null|string    $strategy Strategy name (null uses default from config)
     * @return NewAccessToken The newly created replacement token
     */
    public function rotate(AccessToken $token, ?string $strategy = null): NewAccessToken
    {
        /** @var string $strategyName */
        $strategyName = $strategy ?? config('bearer.rotation.default', 'immediate');
        $rotationStrategy = $this->rotationStrategy($strategyName);

        // Create new token preserving all settings from original
        /** @var HasAccessTokens&Model $owner */
        $owner = $token->owner;
        $conductor = $this->for($owner)
            ->abilities($token->abilities ?? [])
            ->environment($token->environment)
            ->metadata($token->metadata ?? []);

        // Preserve context relationship
        if ($token->context !== null) {
            $conductor = $conductor->context($token->context);
        }

        // Preserve boundary relationship
        if ($token->boundary !== null) {
            $conductor = $conductor->boundary($token->boundary);
        }

        if ($token->allowed_ips !== null) {
            $conductor = $conductor->allowedIps($token->allowed_ips);
        }

        if ($token->allowed_domains !== null) {
            $conductor = $conductor->allowedDomains($token->allowed_domains);
        }

        if ($token->rate_limit_per_minute !== null) {
            $conductor = $conductor->rateLimit($token->rate_limit_per_minute);
        }

        $newToken = $conductor->issue($token->type, $token->name);

        // Associate with same group if applicable
        if ($token->group_id !== null) {
            $newToken->accessToken->update(['group_id' => $token->group_id]);
        }

        // Apply the rotation strategy
        $rotationStrategy->rotate($token, $newToken->accessToken);

        $this->auditDriver()->log($token, AuditEvent::Rotated, [
            'strategy' => $strategyName,
            'new_token_id' => $newToken->accessToken->id,
        ]);

        return $newToken;
    }

    /**
     * Retrieve a token type instance by its key.
     *
     * @param  string    $type The token type key (e.g., 'sk', 'pk', 'rk')
     * @return TokenType The token type implementation
     */
    public function tokenType(string $type): TokenType
    {
        return $this->tokenTypes->get($type);
    }

    /**
     * Retrieve a token generator instance by name.
     *
     * @param  null|string    $name The generator name or null to use the default from config
     * @return TokenGenerator The token generator implementation
     */
    public function tokenGenerator(?string $name = null): TokenGenerator
    {
        /** @var string $generatorName */
        $generatorName = $name ?? config('bearer.generator.default', 'seam');

        return $this->tokenGenerators->get($generatorName);
    }

    /**
     * Retrieve a token hasher instance by name.
     *
     * @param  null|string $name The hasher name or null to use the default from config
     * @return TokenHasher The token hasher implementation
     */
    public function tokenHasher(?string $name = null): TokenHasher
    {
        /** @var string $hasherName */
        $hasherName = $name ?? config('bearer.hasher.default', 'sha256');

        return $this->tokenHashers->get($hasherName);
    }

    /**
     * Retrieve an audit driver instance by name.
     *
     * @param  null|string $name The driver name or null to use the default from config
     * @return AuditDriver The audit driver implementation
     */
    public function auditDriver(?string $name = null): AuditDriver
    {
        /** @var string $driverName */
        $driverName = $name ?? config('bearer.audit.driver', 'database');

        return $this->auditDrivers->get($driverName);
    }

    /**
     * Register a custom token type implementation.
     *
     * @param string    $key  Unique identifier for the token type
     * @param TokenType $type The token type implementation to register
     */
    public function registerTokenType(string $key, TokenType $type): void
    {
        $this->tokenTypes->register($key, $type);
    }

    /**
     * Register a custom token generator implementation.
     *
     * @param string         $name      Unique identifier for the generator
     * @param TokenGenerator $generator The generator implementation to register
     */
    public function registerTokenGenerator(string $name, TokenGenerator $generator): void
    {
        $this->tokenGenerators->register($name, $generator);
    }

    /**
     * Register a custom token hasher implementation.
     *
     * @param string      $name   Unique identifier for the hasher
     * @param TokenHasher $hasher The hasher implementation to register
     */
    public function registerTokenHasher(string $name, TokenHasher $hasher): void
    {
        $this->tokenHashers->register($name, $hasher);
    }

    /**
     * Register a custom audit driver implementation.
     *
     * @param string      $name   Unique identifier for the driver
     * @param AuditDriver $driver The audit driver implementation to register
     */
    public function registerAuditDriver(string $name, AuditDriver $driver): void
    {
        $this->auditDrivers->register($name, $driver);
    }

    /**
     * Retrieve a revocation strategy instance by name.
     *
     * @param  null|string        $name The strategy name or null to use the default from config
     * @return RevocationStrategy The revocation strategy implementation
     */
    public function revocationStrategy(?string $name = null): RevocationStrategy
    {
        /** @var string $strategyName */
        $strategyName = $name ?? config('bearer.revocation.default', 'none');

        return $this->revocationStrategies->get($strategyName);
    }

    /**
     * Register a custom revocation strategy implementation.
     *
     * @param string             $name     Unique identifier for the strategy
     * @param RevocationStrategy $strategy The strategy implementation to register
     */
    public function registerRevocationStrategy(string $name, RevocationStrategy $strategy): void
    {
        $this->revocationStrategies->register($name, $strategy);
    }

    /**
     * Retrieve a rotation strategy instance by name.
     *
     * @param  null|string      $name The strategy name or null to use the default from config
     * @return RotationStrategy The rotation strategy implementation
     */
    public function rotationStrategy(?string $name = null): RotationStrategy
    {
        /** @var string $strategyName */
        $strategyName = $name ?? config('bearer.rotation.default', 'immediate');

        return $this->rotationStrategies->get($strategyName);
    }

    /**
     * Register a custom rotation strategy implementation.
     *
     * @param string           $name     Unique identifier for the strategy
     * @param RotationStrategy $strategy The strategy implementation to register
     */
    public function registerRotationStrategy(string $name, RotationStrategy $strategy): void
    {
        $this->rotationStrategies->register($name, $strategy);
    }

    /**
     * Get the personal access token model class name.
     *
     * @return class-string<AccessToken> The model class name
     */
    public function accessTokenModel(): string
    {
        return BearerConfig::accessTokenModel();
    }

    /**
     * Set a custom personal access token model class.
     *
     * @param class-string<AccessToken> $model The custom model class to use
     */
    public function useAccessTokenModel(string $model): void
    {
        BearerConfig::useAccessTokenModel($model);
    }

    /**
     * Get the token group model class name.
     *
     * @return class-string The model class name
     */
    public function tokenGroupModel(): string
    {
        return BearerConfig::tokenGroupModel();
    }

    /**
     * Set a custom token group model class.
     *
     * @param class-string $model The custom model class to use
     */
    public function useAccessTokenGroupModel(string $model): void
    {
        BearerConfig::useAccessTokenGroupModel($model);
    }

    /**
     * Set the current authenticated user for testing.
     *
     * Creates a testing token with the specified abilities and authenticates the
     * user in the application. Primarily used in test scenarios to simulate
     * authenticated API requests without going through the full authentication flow.
     *
     * @param  Authenticatable&HasAccessTokens $user      The user to authenticate
     * @param  array<string>                   $abilities Token abilities (defaults to ['*'] for all)
     * @param  null|string                     $type      Optional token type identifier
     * @param  string                          $guard     Authentication guard name (defaults to 'bearer')
     * @return Authenticatable                 The authenticated user instance
     */
    public function actingAs(Authenticatable $user, array $abilities = [], ?string $type = null, string $guard = 'bearer'): Authenticatable
    {
        $token = new TestingToken(
            abilities: $abilities === [] ? ['*'] : $abilities,
            type: $type,
        );

        $user->withAccessToken($token);

        if (property_exists($user, 'wasRecentlyCreated') && $user->wasRecentlyCreated !== null && $user->wasRecentlyCreated) {
            $user->wasRecentlyCreated = false;
        }

        Auth::guard($guard)->setUser($user);

        Auth::shouldUse($guard);

        return $user;
    }

    /**
     * Set the callback for custom token retrieval from requests.
     *
     * @param null|(Closure(Request): (null|string)) $callback The token retrieval callback or null to reset
     */
    public function getAccessTokenFromRequestUsing(?Closure $callback): void
    {
        BearerConfig::getAccessTokenFromRequestUsing($callback);
    }

    /**
     * Set the callback for custom token authentication.
     *
     * @param null|Closure(AccessToken, Request): bool $callback The authentication callback or null to reset
     */
    public function authenticateAccessTokensUsing(?Closure $callback): void
    {
        BearerConfig::authenticateAccessTokensUsing($callback);
    }
}
