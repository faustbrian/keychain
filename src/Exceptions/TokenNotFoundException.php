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
 * Exception thrown when a requested token cannot be found.
 *
 * This exception occurs when attempting to retrieve a token by its identifier
 * (ID or prefix) but no matching token exists in the system. This can happen
 * when tokens are deleted, not yet created, or when using incorrect identifiers.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenNotFoundException extends RuntimeException
{
    /**
     * Create an exception for a token not found by its prefix.
     *
     * This occurs when searching for a token using its prefix (the public
     * identifier shown in plain text) but no token with that prefix exists.
     *
     * @param  string $prefix The token prefix that was not found
     * @return self   Exception instance with descriptive error message
     */
    public static function forPrefix(string $prefix): self
    {
        return new self(sprintf("Token with prefix '%s' not found.", $prefix));
    }

    /**
     * Create an exception for a token not found by its ID.
     *
     * This occurs when searching for a token using its database ID but
     * no token with that ID exists in the system.
     *
     * @param  int|string $id The token ID that was not found
     * @return self       Exception instance with descriptive error message
     */
    public static function forId(int|string $id): self
    {
        return new self(sprintf("Token with ID '%s' not found.", $id));
    }
}
