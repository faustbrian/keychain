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
 * Exception thrown when an unregistered token generator is requested.
 *
 * Token generators are responsible for creating unique token strings. This
 * exception occurs when attempting to use a generator that has not been
 * registered in the token generator registry.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenGeneratorNotRegisteredException extends InvalidArgumentException
{
    /**
     * Create an exception for an unregistered token generator.
     *
     * This occurs when code references a token generator by name that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered generator
     * @return self   Exception instance with descriptive error message
     */
    public static function forName(string $name): self
    {
        return new self(sprintf('Token generator "%s" is not registered.', $name));
    }

    /**
     * Create an exception when no default generator is registered.
     *
     * This occurs when requesting the default generator but none has
     * been set or registered.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function noDefault(): self
    {
        return new self('No default token generator is registered.');
    }

    /**
     * Create an exception when trying to set an unregistered generator as default.
     *
     * This occurs when attempting to set a generator as the default that
     * has not been registered in the registry.
     *
     * @param  string $name The name of the unregistered generator
     * @return self   Exception instance with descriptive error message
     */
    public static function cannotSetAsDefault(string $name): self
    {
        return new self(sprintf('Cannot set unregistered generator "%s" as default.', $name));
    }
}
