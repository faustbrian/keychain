<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use InvalidArgumentException;

use function sprintf;

/**
 * Exception thrown when an unregistered audit driver is requested.
 *
 * Audit drivers are responsible for logging token-related events. This
 * exception occurs when attempting to use a driver that has not been
 * registered in the audit driver registry.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AuditDriverNotRegisteredException extends InvalidArgumentException
{
    /**
     * Create an exception for an unregistered audit driver.
     *
     * This occurs when code references an audit driver by name that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered driver
     * @return self   Exception instance with descriptive error message
     */
    public static function forName(string $name): self
    {
        return new self(sprintf('Audit driver "%s" is not registered.', $name));
    }

    /**
     * Create an exception when no default driver is registered.
     *
     * This occurs when requesting the default driver but none has
     * been set or registered.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function noDefault(): self
    {
        return new self('No default audit driver is registered.');
    }

    /**
     * Create an exception when trying to set an unregistered driver as default.
     *
     * This occurs when attempting to set a driver as the default that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered driver
     * @return self   Exception instance with descriptive error message
     */
    public static function cannotSetAsDefault(string $name): self
    {
        return new self(sprintf('Cannot set unregistered driver "%s" as default.', $name));
    }
}
