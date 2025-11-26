<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Exceptions;

use RuntimeException;

use function sprintf;

/**
 * Exception thrown when a token hasher is not registered.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenHasherNotRegisteredException extends RuntimeException
{
    /**
     * Create an exception for an unregistered hasher.
     *
     * @param string $name The hasher name that was not found
     */
    public static function forHasher(string $name): self
    {
        return new self(sprintf("Token hasher '%s' is not registered.", $name));
    }

    /**
     * Create an exception for when no default hasher is set.
     */
    public static function noDefault(): self
    {
        return new self('No default token hasher has been set.');
    }
}
