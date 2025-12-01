<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\RotationStrategies;

use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Exceptions\RotationStrategyNotRegisteredException;

use function array_key_exists;
use function array_keys;

/**
 * Registry for managing rotation strategy implementations.
 *
 * Provides a centralized location for registering, retrieving, and managing
 * different token rotation strategies. Allows applications to configure which
 * strategy to use as the default and switch between implementations as needed.
 *
 * Example usage:
 * ```php
 * $registry = new RotationStrategyRegistry();
 *
 * // Register strategies
 * $registry->register('immediate', new ImmediateStrategy());
 * $registry->register('grace_period', new GracePeriodStrategy(60));
 * $registry->register('dual_valid', new DualValidStrategy());
 *
 * // Retrieve a specific strategy
 * $strategy = $registry->get('grace_period');
 *
 * // Check if a strategy exists
 * if ($registry->has('immediate')) {
 *     // ...
 * }
 *
 * // Get the default strategy
 * $default = $registry->default();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RotationStrategyRegistry
{
    /**
     * Registered rotation strategies indexed by name.
     *
     * @var array<string, RotationStrategy>
     */
    private array $strategies = [];

    /**
     * Name of the default strategy to use when none is specified.
     */
    private ?string $defaultStrategy = null;

    /**
     * Register a rotation strategy with a given name.
     *
     * If this is the first strategy registered and no default has been set,
     * it will automatically become the default strategy.
     *
     * @param string           $name     Unique identifier for this strategy
     * @param RotationStrategy $strategy The strategy implementation to register
     */
    public function register(string $name, RotationStrategy $strategy): void
    {
        $this->strategies[$name] = $strategy;

        // Set the first registered strategy as default if none is set
        if ($this->defaultStrategy === null) {
            $this->defaultStrategy = $name;
        }
    }

    /**
     * Retrieve a registered rotation strategy by name.
     *
     * @param string $name The name of the strategy to retrieve
     *
     * @throws RotationStrategyNotRegisteredException If the strategy is not registered
     *
     * @return RotationStrategy The requested strategy instance
     */
    public function get(string $name): RotationStrategy
    {
        if (!$this->has($name)) {
            throw RotationStrategyNotRegisteredException::forName($name);
        }

        return $this->strategies[$name];
    }

    /**
     * Check if a rotation strategy is registered.
     *
     * @param  string $name The name of the strategy to check
     * @return bool   True if registered, false otherwise
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->strategies);
    }

    /**
     * Get the default rotation strategy.
     *
     * @throws RotationStrategyNotRegisteredException If no strategies are registered
     *
     * @return RotationStrategy The default strategy instance
     */
    public function default(): RotationStrategy
    {
        if ($this->defaultStrategy === null) {
            throw RotationStrategyNotRegisteredException::noDefault();
        }

        return $this->get($this->defaultStrategy);
    }

    /**
     * Set the default rotation strategy by name.
     *
     * @param string $name The name of the strategy to set as default
     *
     * @throws RotationStrategyNotRegisteredException If the strategy is not registered
     */
    public function setDefault(string $name): void
    {
        if (!$this->has($name)) {
            throw RotationStrategyNotRegisteredException::cannotSetAsDefault($name);
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
