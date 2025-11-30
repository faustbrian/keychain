<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

use function sprintf;

/**
 * Exception thrown when a token hasher is not registered.
 *
 * Token hashers are responsible for securely hashing and verifying token values.
 * This exception occurs when attempting to use a hasher that hasn't been registered
 * with the BearerManager, or when no default hasher is configured.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenHasherNotRegisteredException extends RuntimeException
{
    /**
     * Create an exception for an unregistered hasher.
     *
     * This occurs when attempting to retrieve or use a token hasher by name
     * that hasn't been registered via registerTokenHasher() on the BearerManager.
     *
     * @param  string $name The hasher name that was not found
     * @return self   Exception instance with descriptive error message
     */
    public static function forHasher(string $name): self
    {
        return new self(sprintf("Token hasher '%s' is not registered.", $name));
    }

    /**
     * Create an exception for when no default hasher is set.
     *
     * This occurs when attempting to use the default hasher but no default
     * has been configured in the bearer configuration.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function noDefault(): self
    {
        return new self('No default token hasher has been set.');
    }
}
