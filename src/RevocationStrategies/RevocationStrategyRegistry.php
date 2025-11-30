<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\RevocationStrategies;

use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Exceptions\RevocationStrategyNotRegisteredException;

use function array_key_exists;
use function array_keys;

/**
 * Registry for managing revocation strategy implementations.
 *
 * Provides a centralized location for registering, retrieving, and managing
 * different token revocation strategies. Allows applications to configure which
 * strategy to use as the default and switch between implementations as needed.
 *
 * Example usage:
 * ```php
 * $registry = new RevocationStrategyRegistry();
 *
 * // Register strategies
 * $registry->register('none', new NoneStrategy());
 * $registry->register('cascade', new CascadeStrategy());
 * $registry->register('partial', new PartialCascadeStrategy(['sk', 'rk']));
 *
 * // Retrieve a specific strategy
 * $strategy = $registry->get('cascade');
 *
 * // Check if a strategy exists
 * if ($registry->has('timed')) {
 *     // ...
 * }
 *
 * // Get the default strategy
 * $default = $registry->default();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RevocationStrategyRegistry
{
    /**
     * Registered revocation strategies.
     *
     * @var array<string, RevocationStrategy>
     */
    private array $strategies = [];

    /**
     * Name of the default strategy.
     */
    private ?string $defaultStrategy = null;

    /**
     * Register a revocation strategy with a given name.
     *
     * Stores the strategy in the registry and automatically sets it as the default
     * if no default has been configured yet. This ensures the registry always has
     * a usable default strategy.
     *
     * @param string             $name     Unique identifier for this strategy
     * @param RevocationStrategy $strategy The strategy implementation to register
     */
    public function register(string $name, RevocationStrategy $strategy): void
    {
        $this->strategies[$name] = $strategy;

        // Set the first registered strategy as default if none is set
        if ($this->defaultStrategy === null) {
            $this->defaultStrategy = $name;
        }
    }

    /**
     * Retrieve a registered revocation strategy by name.
     *
     * @param string $name The name of the strategy to retrieve
     *
     * @throws RevocationStrategyNotRegisteredException If the strategy is not registered
     *
     * @return RevocationStrategy The requested strategy instance
     */
    public function get(string $name): RevocationStrategy
    {
        if (!$this->has($name)) {
            throw RevocationStrategyNotRegisteredException::forName($name);
        }

        return $this->strategies[$name];
    }

    /**
     * Check if a revocation strategy is registered.
     *
     * @param  string $name The name of the strategy to check
     * @return bool   True if registered, false otherwise
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->strategies);
    }

    /**
     * Get the default revocation strategy.
     *
     * @throws RevocationStrategyNotRegisteredException If no strategies are registered
     *
     * @return RevocationStrategy The default strategy instance
     */
    public function default(): RevocationStrategy
    {
        if ($this->defaultStrategy === null) {
            throw RevocationStrategyNotRegisteredException::noDefault();
        }

        return $this->get($this->defaultStrategy);
    }

    /**
     * Set the default revocation strategy by name.
     *
     * Changes which strategy will be used when no specific strategy is requested.
     * The strategy must already be registered before it can be set as default.
     *
     * @param string $name The name of the strategy to set as default
     *
     * @throws RevocationStrategyNotRegisteredException If the strategy is not registered
     */
    public function setDefault(string $name): void
    {
        if (!$this->has($name)) {
            throw RevocationStrategyNotRegisteredException::cannotSetAsDefault($name);
        }

        $this->defaultStrategy = $name;
    }

    /**
     * Get all registered strategy names.
     *
     * @return array<string> List of registered strategy names
     */
    public function all(): array
    {
        return array_keys($this->strategies);
    }
}
