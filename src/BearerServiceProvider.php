<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer;

use Cline\Bearer\AuditDrivers\AuditDriverRegistry;
use Cline\Bearer\AuditDrivers\DatabaseAuditDriver;
use Cline\Bearer\AuditDrivers\NullAuditDriver;
use Cline\Bearer\AuditDrivers\SpatieActivityLogDriver;
use Cline\Bearer\Console\Commands\PruneAuditLogsCommand;
use Cline\Bearer\Console\Commands\PruneExpiredCommand;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Contracts\TokenType;
use Cline\Bearer\Database\ModelRegistry;
use Cline\Bearer\Guards\BearerGuard;
use Cline\Bearer\Http\Middleware\EnsureFrontendRequestsAreStateful;
use Cline\Bearer\RevocationStrategies\CascadeStrategy;
use Cline\Bearer\RevocationStrategies\NoneStrategy;
use Cline\Bearer\RevocationStrategies\PartialCascadeStrategy;
use Cline\Bearer\RevocationStrategies\RevocationStrategyRegistry;
use Cline\Bearer\RevocationStrategies\TimedStrategy;
use Cline\Bearer\RotationStrategies\DualValidStrategy;
use Cline\Bearer\RotationStrategies\GracePeriodStrategy;
use Cline\Bearer\RotationStrategies\ImmediateInvalidationStrategy;
use Cline\Bearer\RotationStrategies\RotationStrategyRegistry;
use Cline\Bearer\TokenGenerators\RandomTokenGenerator;
use Cline\Bearer\TokenGenerators\SeamTokenGenerator;
use Cline\Bearer\TokenGenerators\TokenGeneratorRegistry;
use Cline\Bearer\TokenGenerators\UuidTokenGenerator;
use Cline\Bearer\TokenHashers\Sha256TokenHasher;
use Cline\Bearer\TokenHashers\Sha512TokenHasher;
use Cline\Bearer\TokenHashers\TokenHasherRegistry;
use Cline\Bearer\TokenTypes\ConfigurableTokenType;
use Cline\Bearer\TokenTypes\TokenTypeRegistry;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Override;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

use function app;
use function array_key_exists;
use function array_merge;
use function assert;
use function class_exists;
use function config;
use function is_array;
use function is_string;
use function request;
use function tap;

/**
 * Service provider for the Bearer API token package.
 *
 * Registers the Bearer authentication guard, token type registry, token generator
 * registry, audit driver registry, and console commands. Sets up middleware priority
 * and configures polymorphic relationship key mappings.
 *
 * Key features:
 * - Custom authentication guard for token-based API authentication
 * - Pluggable token type system with registry
 * - Configurable token generators (Seam, UUID, Random)
 * - Audit driver system for token activity logging
 * - Console commands for token and audit log maintenance
 * - Polymorphic relationship support with Morpheus
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class BearerServiceProvider extends PackageServiceProvider
{
    /**
     * Configure the package settings.
     *
     * Defines package configuration including the package name, config file,
     * database migration for token storage tables, and console commands.
     *
     * @param Package $package The package configuration instance to configure
     */
    public function configurePackage(Package $package): void
    {
        $package
            ->name('bearer')
            ->hasConfigFile()
            ->hasMigrations(['create_bearer_tables'])
            ->hasCommands([
                PruneExpiredCommand::class,
                PruneAuditLogsCommand::class,
            ]);
    }

    /**
     * Register the package's services in the container.
     *
     * Registers all registries as singletons and configures their default
     * implementations based on package configuration. This includes token types,
     * generators, hashers, audit drivers, and revocation/rotation strategies.
     */
    #[Override()]
    public function registeringPackage(): void
    {
        $this->registerTokenTypeRegistry();
        $this->registerTokenGeneratorRegistry();
        $this->registerTokenHasherRegistry();
        $this->registerAuditDriverRegistry();
        $this->registerRevocationStrategyRegistry();
        $this->registerRotationStrategyRegistry();
        $this->registerBearerManager();
    }

    /**
     * Bootstrap the package's services.
     *
     * Configures the authentication guard, registers middleware priority,
     * and sets up polymorphic relationship key mappings. This runs after
     * all service providers have been registered.
     */
    #[Override()]
    public function bootingPackage(): void
    {
        $this->configureMorphKeyMaps();
        $this->configureGuard();
        $this->configureMiddleware();
    }

    /**
     * Register the token type registry singleton.
     *
     * Loads token types from configuration and registers them in the registry.
     * Supports both custom class-based types and ConfigurableTokenType instances
     * defined in the configuration file.
     */
    private function registerTokenTypeRegistry(): void
    {
        $this->app->singleton(function ($app): TokenTypeRegistry {
            assert($app instanceof Application);
            $registry = new TokenTypeRegistry();

            /** @var array<string, mixed> $types */
            $types = Config::get('bearer.types', []);

            foreach ($types as $key => $config) {
                if (!is_string($key)) {
                    continue;
                }

                if (!is_array($config)) {
                    continue;
                }

                // Skip non-token-type config entries like group_helpers
                if ($key === 'group_helpers') {
                    continue;
                }

                if (array_key_exists('class', $config) && is_string($config['class']) && class_exists($config['class'])) {
                    /** @var TokenType $tokenType */
                    $tokenType = $app->make($config['class']);
                    $registry->register($key, $tokenType);
                } else {
                    /** @var array<string, mixed> $config */
                    $registry->register($key, ConfigurableTokenType::fromConfig($config));
                }
            }

            return $registry;
        });
    }

    /**
     * Register the token generator registry singleton.
     *
     * Loads token generators from configuration and sets the default generator.
     * Provides built-in support for Seam, UUID, and Random generators, plus any
     * custom generators defined in the configuration.
     */
    private function registerTokenGeneratorRegistry(): void
    {
        $this->app->singleton(function ($app): TokenGeneratorRegistry {
            assert($app instanceof Application);
            $registry = new TokenGeneratorRegistry();

            // Register built-in generators
            $builtInGenerators = [
                'seam' => SeamTokenGenerator::class,
                'uuid' => UuidTokenGenerator::class,
                'random' => RandomTokenGenerator::class,
            ];

            foreach ($builtInGenerators as $name => $class) {
                /** @var TokenGenerator $generator */
                $generator = $app->make($class);
                $registry->register($name, $generator);
            }

            // Register custom generators from config
            /** @var array<string, class-string> $drivers */
            $drivers = Config::get('bearer.generator.drivers', []);

            foreach ($drivers as $name => $class) {
                if (!is_string($name)) {
                    continue;
                }

                if (!is_string($class)) {
                    continue;
                }

                if (class_exists($class) && !array_key_exists($name, $builtInGenerators)) {
                    /** @var TokenGenerator $generator */
                    $generator = $app->make($class);
                    $registry->register($name, $generator);
                }
            }

            // Set default generator
            /** @var string $default */
            $default = Config::get('bearer.generator.default', 'seam');

            if (is_string($default) && $registry->has($default)) {
                $registry->setDefault($default);
            }

            return $registry;
        });
    }

    /**
     * Register the token hasher registry singleton.
     *
     * Loads token hashers from configuration and sets the default hasher.
     * Provides built-in support for SHA-256 and SHA-512 hashers, plus any
     * custom hashers defined in the configuration.
     */
    private function registerTokenHasherRegistry(): void
    {
        $this->app->singleton(function ($app): TokenHasherRegistry {
            assert($app instanceof Application);
            $registry = new TokenHasherRegistry();

            // Register built-in hashers
            $builtInHashers = [
                'sha256' => Sha256TokenHasher::class,
                'sha512' => Sha512TokenHasher::class,
            ];

            foreach ($builtInHashers as $name => $class) {
                /** @var TokenHasher $hasher */
                $hasher = $app->make($class);
                $registry->register($name, $hasher);
            }

            // Register custom hashers from config
            /** @var array<string, class-string> $drivers */
            $drivers = Config::get('bearer.hasher.drivers', []);

            foreach ($drivers as $name => $class) {
                if (!is_string($name)) {
                    continue;
                }

                if (!is_string($class)) {
                    continue;
                }

                if (class_exists($class) && !array_key_exists($name, $builtInHashers)) {
                    /** @var TokenHasher $hasher */
                    $hasher = $app->make($class);
                    $registry->register($name, $hasher);
                }
            }

            // Set default hasher
            /** @var string $default */
            $default = Config::get('bearer.hasher.default', 'sha256');

            if (is_string($default) && $registry->has($default)) {
                $registry->setDefault($default);
            }

            return $registry;
        });
    }

    /**
     * Register the audit driver registry singleton.
     *
     * Loads audit drivers from configuration and sets the default driver.
     * Provides built-in support for Database, Null, and Spatie Activity Log drivers,
     * plus any custom drivers defined in the configuration.
     */
    private function registerAuditDriverRegistry(): void
    {
        $this->app->singleton(function ($app): AuditDriverRegistry {
            assert($app instanceof Application);
            $registry = new AuditDriverRegistry();

            // Register built-in drivers
            $builtInDrivers = [
                'database' => DatabaseAuditDriver::class,
                'null' => NullAuditDriver::class,
                'spatie' => SpatieActivityLogDriver::class,
            ];

            foreach ($builtInDrivers as $name => $class) {
                /** @var AuditDriver $driver */
                $driver = $app->make($class);
                $registry->register($name, $driver);
            }

            // Register custom drivers from config
            /** @var array<string, mixed> $drivers */
            $drivers = Config::get('bearer.audit.drivers', []);

            foreach ($drivers as $name => $config) {
                if (!is_string($name)) {
                    continue;
                }

                if (!is_array($config)) {
                    continue;
                }

                if (array_key_exists('class', $config) && is_string($config['class']) && class_exists($config['class']) && !array_key_exists($name, $builtInDrivers)) {
                    /** @var AuditDriver $driver */
                    $driver = $app->make($config['class']);
                    $registry->register($name, $driver);
                }
            }

            // Set default driver
            /** @var string $default */
            $default = Config::get('bearer.audit.driver', 'database');

            if (is_string($default) && $registry->has($default)) {
                $registry->setDefault($default);
            }

            return $registry;
        });
    }

    /**
     * Register the revocation strategy registry singleton.
     *
     * Loads revocation strategies from configuration and sets the default strategy.
     * Provides built-in support for None, Cascade, Partial, and Timed strategies,
     * plus any custom strategies defined in the configuration.
     */
    private function registerRevocationStrategyRegistry(): void
    {
        $this->app->singleton(function ($app): RevocationStrategyRegistry {
            assert($app instanceof Application);
            $registry = new RevocationStrategyRegistry();

            // Register built-in strategies
            $registry->register('none', $app->make(NoneStrategy::class));
            $registry->register('cascade', $app->make(CascadeStrategy::class));

            // Partial strategy with configurable types
            /** @var array<int, string> $partialTypes */
            $partialTypes = Config::get('bearer.revocation.drivers.partial.types', ['sk', 'rk']);
            $registry->register('partial', new PartialCascadeStrategy($partialTypes));

            // Timed strategy with configurable delay
            /** @var int $delayMinutes */
            $delayMinutes = Config::get('bearer.revocation.drivers.timed.delay_minutes', 60);
            $registry->register('timed', new TimedStrategy($delayMinutes));

            // Register custom strategies from config
            /** @var array<string, mixed> $drivers */
            $drivers = Config::get('bearer.revocation.drivers', []);

            foreach ($drivers as $name => $config) {
                if (!is_string($name)) {
                    continue;
                }

                if (!is_array($config)) {
                    continue;
                }

                if (!array_key_exists('class', $config)) {
                    continue;
                }

                if (!is_string($config['class'])) {
                    continue;
                }

                if (!class_exists($config['class'])) {
                    continue;
                }

                if ($registry->has($name)) {
                    continue;
                }

                /** @var RevocationStrategy $strategy */
                $strategy = $app->make($config['class']);
                $registry->register($name, $strategy);
            }

            // Set default strategy
            /** @var string $default */
            $default = Config::get('bearer.revocation.default', 'none');

            if (is_string($default) && $registry->has($default)) {
                $registry->setDefault($default);
            }

            return $registry;
        });
    }

    /**
     * Register the rotation strategy registry singleton.
     *
     * Loads rotation strategies from configuration and sets the default strategy.
     * Provides built-in support for Immediate, GracePeriod, and DualValid strategies,
     * plus any custom strategies defined in the configuration.
     */
    private function registerRotationStrategyRegistry(): void
    {
        $this->app->singleton(function ($app): RotationStrategyRegistry {
            assert($app instanceof Application);
            $registry = new RotationStrategyRegistry();

            // Register built-in strategies
            $registry->register('immediate', $app->make(ImmediateInvalidationStrategy::class));
            $registry->register('dual_valid', $app->make(DualValidStrategy::class));

            // Grace period strategy with configurable duration
            /** @var int $gracePeriodMinutes */
            $gracePeriodMinutes = Config::get('bearer.rotation.drivers.grace_period.grace_period_minutes', 60);
            $registry->register('grace_period', new GracePeriodStrategy($gracePeriodMinutes));

            // Register custom strategies from config
            /** @var array<string, mixed> $drivers */
            $drivers = Config::get('bearer.rotation.drivers', []);

            foreach ($drivers as $name => $config) {
                if (!is_string($name)) {
                    continue;
                }

                if (!is_array($config)) {
                    continue;
                }

                if (!array_key_exists('class', $config)) {
                    continue;
                }

                if (!is_string($config['class'])) {
                    continue;
                }

                if (!class_exists($config['class'])) {
                    continue;
                }

                if ($registry->has($name)) {
                    continue;
                }

                /** @var RotationStrategy $strategy */
                $strategy = $app->make($config['class']);
                $registry->register($name, $strategy);
            }

            // Set default strategy
            /** @var string $default */
            $default = Config::get('bearer.rotation.default', 'immediate');

            if (is_string($default) && $registry->has($default)) {
                $registry->setDefault($default);
            }

            return $registry;
        });
    }

    /**
     * Register the bearer manager singleton.
     *
     * Wires up all registries into the central BearerManager instance,
     * creating the main entry point for token operations.
     */
    private function registerBearerManager(): void
    {
        $this->app->singleton(function ($app): BearerManager {
            assert($app instanceof Application);

            return new BearerManager(
                $app->make(TokenTypeRegistry::class),
                $app->make(TokenGeneratorRegistry::class),
                $app->make(TokenHasherRegistry::class),
                $app->make(AuditDriverRegistry::class),
                $app->make(RevocationStrategyRegistry::class),
                $app->make(RotationStrategyRegistry::class),
            );
        });
    }

    /**
     * Configure the Bearer authentication guard.
     *
     * Registers the 'bearer' guard driver and sets up the auth configuration.
     * The guard handles both stateful session authentication and bearer token validation.
     */
    private function configureGuard(): void
    {
        /** @var array<string, mixed> $existingGuardConfig */
        $existingGuardConfig = config('auth.guards.bearer', []);

        config([
            'auth.guards.bearer' => array_merge([
                'driver' => 'bearer',
                'provider' => null,
            ], $existingGuardConfig),
        ]);

        Auth::resolved(function (AuthManager $auth): void {
            $auth->extend('bearer', function ($app, $name, array $config) use ($auth): RequestGuard {
                /** @var array<string, mixed> $config */
                return tap($this->createGuard($auth, $config), function ($guard): void {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }

    /**
     * Create a new Bearer request guard instance.
     *
     * @param  AuthManager          $auth   The authentication manager
     * @param  array<string, mixed> $config Guard configuration
     * @return RequestGuard         The configured request guard
     */
    private function createGuard(AuthManager $auth, array $config): RequestGuard
    {
        /** @var null|int $expiration */
        $expiration = Config::get('bearer.expiration');

        /** @var null|string $provider */
        $provider = $config['provider'] ?? null;

        return new RequestGuard(
            new BearerGuard(
                $auth,
                $this->app->make(BearerManager::class),
                $expiration,
                $provider,
            ),
            request(),
            $auth->createUserProvider($provider),
        );
    }

    /**
     * Configure middleware priority.
     *
     * Ensures the EnsureFrontendRequestsAreStateful middleware runs early
     * in the middleware stack for proper session/CSRF handling.
     */
    private function configureMiddleware(): void
    {
        $kernel = app()->make(Kernel::class);
        assert($kernel instanceof HttpKernel);
        $kernel->prependToMiddlewarePriority(EnsureFrontendRequestsAreStateful::class);
    }

    /**
     * Configure polymorphic relationship key mappings.
     *
     * Applies morphKeyMap or enforceMorphKeyMap configuration based on which is defined.
     * This enables different models to use different primary key types in polymorphic
     * relationships (e.g., User with 'uuid', Team with 'id').
     */
    private function configureMorphKeyMaps(): void
    {
        $morphKeyMap = Config::get('bearer.morphKeyMap', []);
        $enforceMorphKeyMap = Config::get('bearer.enforceMorphKeyMap', []);

        if (!is_array($morphKeyMap)) {
            $morphKeyMap = [];
        }

        if (!is_array($enforceMorphKeyMap)) {
            $enforceMorphKeyMap = [];
        }

        $hasMorphKeyMap = $morphKeyMap !== [];
        $hasEnforceMorphKeyMap = $enforceMorphKeyMap !== [];

        // Only apply if at least one is configured
        if (!$hasMorphKeyMap && !$hasEnforceMorphKeyMap) {
            return;
        }

        $registry = $this->app->make(ModelRegistry::class);

        if ($hasEnforceMorphKeyMap) {
            /** @var array<class-string, string> $enforceMorphKeyMap */
            $registry->enforceMorphKeyMap($enforceMorphKeyMap);
        } elseif ($hasMorphKeyMap) {
            /** @var array<class-string, string> $morphKeyMap */
            $registry->morphKeyMap($morphKeyMap);
        }
    }
}
