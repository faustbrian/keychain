<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain;

use Cline\Keychain\AuditDrivers\AuditDriverRegistry;
use Cline\Keychain\Conductors\TokenIssuanceConductor;
use Cline\Keychain\Conductors\TokenRevocationConductor;
use Cline\Keychain\Contracts\AuditDriver;
use Cline\Keychain\Contracts\HasApiTokens;
use Cline\Keychain\Contracts\RevocationStrategy;
use Cline\Keychain\Contracts\RotationStrategy;
use Cline\Keychain\Contracts\TokenGenerator;
use Cline\Keychain\Contracts\TokenHasher;
use Cline\Keychain\Contracts\TokenType;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Enums\AuditEvent;
use Cline\Keychain\RevocationStrategies\RevocationStrategyRegistry;
use Cline\Keychain\RotationStrategies\RotationStrategyRegistry;
use Cline\Keychain\Testing\TestingToken;
use Cline\Keychain\TokenGenerators\TokenGeneratorRegistry;
use Cline\Keychain\TokenHashers\TokenHasherRegistry;
use Cline\Keychain\TokenTypes\TokenTypeRegistry;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
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
final readonly class KeychainManager
{
    /**
     * Create a new keychain manager instance.
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
     * Create a token issuance conductor for the given tokenable model.
     *
     * @param HasApiTokens&Model $tokenable
     */
    public function for(Model $tokenable): TokenIssuanceConductor
    {
        return new TokenIssuanceConductor($this, $tokenable);
    }

    /**
     * Create a token revocation conductor for the given token.
     *
     * Provides a fluent interface for configuring and executing token
     * revocation operations with various modes and metadata.
     */
    public function createRevocationConductor(PersonalAccessToken $token): TokenRevocationConductor
    {
        return new TokenRevocationConductor($this, $token);
    }

    /**
     * Find a personal access token by its plain-text token string.
     */
    public function findToken(string $token): ?PersonalAccessToken
    {
        $hasher = $this->tokenHasher();

        // Tokens without | prefix are looked up by hash directly
        if (!str_contains($token, '|')) {
            /** @var null|PersonalAccessToken */
            return PersonalAccessToken::query()
                ->where('token', $hasher->hash($token))
                ->first();
        }

        // Tokens with id|plaintext format use id lookup + hash verification
        [$id, $plainToken] = explode('|', $token, 2);

        $instance = PersonalAccessToken::query()->find($id);

        if ($instance instanceof PersonalAccessToken && $hasher->verify($plainToken, $instance->token)) {
            return $instance;
        }

        return null;
    }

    /**
     * Find a personal access token by its prefix.
     */
    public function findByPrefix(string $prefix): ?PersonalAccessToken
    {
        /** @var null|PersonalAccessToken */
        return PersonalAccessToken::query()
            ->where('prefix', $prefix)
            ->first();
    }

    /**
     * Revoke a personal access token using the specified strategy.
     *
     * @param PersonalAccessToken $token    The token to revoke
     * @param null|string         $strategy Strategy name (null uses default from config)
     */
    public function revoke(PersonalAccessToken $token, ?string $strategy = null): void
    {
        /** @var string $strategyName */
        $strategyName = $strategy ?? config('keychain.revocation.default', 'none');
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
     * @param PersonalAccessToken $token    The token to rotate
     * @param null|string         $strategy Strategy name (null uses default from config)
     */
    public function rotate(PersonalAccessToken $token, ?string $strategy = null): NewAccessToken
    {
        /** @var string $strategyName */
        $strategyName = $strategy ?? config('keychain.rotation.default', 'immediate');
        $rotationStrategy = $this->rotationStrategy($strategyName);

        // Create new token preserving all settings from original
        /** @var HasApiTokens&Model $tokenable */
        $tokenable = $token->tokenable;
        $conductor = $this->for($tokenable)
            ->abilities($token->abilities ?? [])
            ->environment($token->environment)
            ->metadata($token->metadata ?? []);

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
     * Get a token type instance by key.
     */
    public function tokenType(string $type): TokenType
    {
        return $this->tokenTypes->get($type);
    }

    /**
     * Get a token generator instance by name.
     */
    public function tokenGenerator(?string $name = null): TokenGenerator
    {
        /** @var string $generatorName */
        $generatorName = $name ?? config('keychain.generator.default', 'seam');

        return $this->tokenGenerators->get($generatorName);
    }

    /**
     * Get a token hasher instance by name.
     */
    public function tokenHasher(?string $name = null): TokenHasher
    {
        /** @var string $hasherName */
        $hasherName = $name ?? config('keychain.hasher.default', 'sha256');

        return $this->tokenHashers->get($hasherName);
    }

    /**
     * Get an audit driver instance by name.
     */
    public function auditDriver(?string $name = null): AuditDriver
    {
        /** @var string $driverName */
        $driverName = $name ?? config('keychain.audit.driver', 'database');

        return $this->auditDrivers->get($driverName);
    }

    /**
     * Register a token type.
     */
    public function registerTokenType(string $key, TokenType $type): void
    {
        $this->tokenTypes->register($key, $type);
    }

    /**
     * Register a token generator.
     */
    public function registerTokenGenerator(string $name, TokenGenerator $generator): void
    {
        $this->tokenGenerators->register($name, $generator);
    }

    /**
     * Register a token hasher.
     */
    public function registerTokenHasher(string $name, TokenHasher $hasher): void
    {
        $this->tokenHashers->register($name, $hasher);
    }

    /**
     * Register an audit driver.
     */
    public function registerAuditDriver(string $name, AuditDriver $driver): void
    {
        $this->auditDrivers->register($name, $driver);
    }

    /**
     * Get a revocation strategy instance by name.
     */
    public function revocationStrategy(?string $name = null): RevocationStrategy
    {
        /** @var string $strategyName */
        $strategyName = $name ?? config('keychain.revocation.default', 'none');

        return $this->revocationStrategies->get($strategyName);
    }

    /**
     * Register a revocation strategy.
     */
    public function registerRevocationStrategy(string $name, RevocationStrategy $strategy): void
    {
        $this->revocationStrategies->register($name, $strategy);
    }

    /**
     * Get a rotation strategy instance by name.
     */
    public function rotationStrategy(?string $name = null): RotationStrategy
    {
        /** @var string $strategyName */
        $strategyName = $name ?? config('keychain.rotation.default', 'immediate');

        return $this->rotationStrategies->get($strategyName);
    }

    /**
     * Register a rotation strategy.
     */
    public function registerRotationStrategy(string $name, RotationStrategy $strategy): void
    {
        $this->rotationStrategies->register($name, $strategy);
    }

    /**
     * Get the personal access token model class name.
     *
     * @return class-string<PersonalAccessToken>
     */
    public function personalAccessTokenModel(): string
    {
        return KeychainConfig::personalAccessTokenModel();
    }

    /**
     * Set the personal access token model class name.
     *
     * @param class-string<PersonalAccessToken> $model
     */
    public function usePersonalAccessTokenModel(string $model): void
    {
        KeychainConfig::usePersonalAccessTokenModel($model);
    }

    /**
     * Get the token group model class name.
     *
     * @return class-string
     */
    public function tokenGroupModel(): string
    {
        return KeychainConfig::tokenGroupModel();
    }

    /**
     * Set the token group model class name.
     *
     * @param class-string $model
     */
    public function useTokenGroupModel(string $model): void
    {
        KeychainConfig::useTokenGroupModel($model);
    }

    /**
     * Set the current user for the application with the given abilities.
     *
     * @param Authenticatable&HasApiTokens $user
     * @param array<string>                $abilities
     */
    public function actingAs(Authenticatable $user, array $abilities = [], ?string $type = null, string $guard = 'keychain'): Authenticatable
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
     * Specify a callback that should be used to fetch the access token from the request.
     */
    public function getAccessTokenFromRequestUsing(?Closure $callback): void
    {
        KeychainConfig::getAccessTokenFromRequestUsing($callback);
    }

    /**
     * Specify a callback that should be used to authenticate access tokens.
     */
    public function authenticateAccessTokensUsing(?Closure $callback): void
    {
        KeychainConfig::authenticateAccessTokensUsing($callback);
    }
}
