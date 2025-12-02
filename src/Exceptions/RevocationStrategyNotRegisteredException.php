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
 * Exception thrown when an unregistered revocation strategy is requested.
 *
 * Revocation strategies define how tokens are invalidated. This exception
 * occurs when attempting to use a strategy that has not been registered
 * in the revocation strategy registry.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RevocationStrategyNotRegisteredException extends InvalidArgumentException
{
    /**
     * Create an exception for an unregistered revocation strategy.
     *
     * This occurs when code references a revocation strategy by name that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered strategy
     * @return self   Exception instance with descriptive error message
     */
    public static function forName(string $name): self
    {
        return new self(sprintf('Revocation strategy "%s" is not registered.', $name));
    }

    /**
     * Create an exception when no default strategy is registered.
     *
     * This occurs when requesting the default strategy but none has
     * been set or registered.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function noDefault(): self
    {
        return new self('No default revocation strategy is registered.');
    }

    /**
     * Create an exception when trying to set an unregistered strategy as default.
     *
     * This occurs when attempting to set a strategy as the default that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered strategy
     * @return self   Exception instance with descriptive error message
     */
    public static function cannotSetAsDefault(string $name): self
    {
        return new self(sprintf('Cannot set unregistered revocation strategy "%s" as default.', $name));
    }
}
