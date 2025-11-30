<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\AuditDrivers;

use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Exceptions\AuditDriverNotRegisteredException;

use function array_key_exists;
use function array_keys;

/**
 * Registry for managing audit driver implementations.
 *
 * Provides a centralized location for registering, retrieving, and managing
 * different audit driver strategies. Allows applications to configure which
 * driver to use as the default and switch between implementations as needed.
 *
 * This registry pattern enables:
 * - Pluggable audit storage backends
 * - Runtime driver switching
 * - Custom driver implementations
 * - Multiple concurrent drivers
 * - Testing with mock drivers
 *
 * Example usage:
 * ```php
 * $registry = new AuditDriverRegistry();
 *
 * // Register drivers
 * $registry->register('database', new DatabaseAuditDriver());
 * $registry->register('spatie', new SpatieActivityLogDriver('api-tokens'));
 * $registry->register('null', new NullAuditDriver());
 *
 * // Retrieve a specific driver
 * $driver = $registry->get('database');
 *
 * // Check if a driver exists
 * if ($registry->has('spatie')) {
 *     // ...
 * }
 *
 * // Get the default driver
 * $default = $registry->default();
 *
 * // Set a different default
 * $registry->setDefault('spatie');
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AuditDriverRegistry
{
    /**
     * Registered audit drivers.
     *
     * @var array<string, AuditDriver>
     */
    private array $drivers = [];

    /**
     * Name of the default driver.
     */
    private ?string $defaultDriver = null;

    /**
     * Register an audit driver with a given name.
     *
     * @param string      $name   Unique identifier for this driver
     * @param AuditDriver $driver The driver implementation to register
     */
    public function register(string $name, AuditDriver $driver): void
    {
        $this->drivers[$name] = $driver;

        // Set the first registered driver as default if none is set
        if ($this->defaultDriver === null) {
            $this->defaultDriver = $name;
        }
    }

    /**
     * Retrieve a registered audit driver by name.
     *
     * @param string $name The name of the driver to retrieve
     *
     * @throws AuditDriverNotRegisteredException If the driver is not registered
     *
     * @return AuditDriver The requested driver instance
     */
    public function get(string $name): AuditDriver
    {
        if (!$this->has($name)) {
            throw AuditDriverNotRegisteredException::forName($name);
        }

        return $this->drivers[$name];
    }

    /**
     * Check if an audit driver is registered.
     *
     * @param  string $name The name of the driver to check
     * @return bool   True if registered, false otherwise
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->drivers);
    }

    /**
     * Get the default audit driver.
     *
     * @throws AuditDriverNotRegisteredException If no drivers are registered
     *
     * @return AuditDriver The default driver instance
     */
    public function default(): AuditDriver
    {
        if ($this->defaultDriver === null) {
            throw AuditDriverNotRegisteredException::noDefault();
        }

        return $this->get($this->defaultDriver);
    }

    /**
     * Set the default audit driver by name.
     *
     * @param string $name The name of the driver to set as default
     *
     * @throws AuditDriverNotRegisteredException If the driver is not registered
     */
    public function setDefault(string $name): void
    {
        if (!$this->has($name)) {
            throw AuditDriverNotRegisteredException::cannotSetAsDefault($name);
        }

        $this->defaultDriver = $name;
    }

    /**
     * Get all registered driver names.
     *
     * @return array<string> List of registered driver names
     */
    public function all(): array
    {
        return array_keys($this->drivers);
    }
}
