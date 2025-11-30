<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

/**
 * Exception thrown when a token lacks an associated tokenable model.
 *
 * During token rotation, the token must have a valid tokenable relationship
 * that implements the HasApiTokens contract. This exception occurs when the
 * tokenable is null or does not implement the required interface.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingTokenableException extends RuntimeException
{
    /**
     * Create an exception for a token without a valid tokenable model during rotation.
     *
     * This occurs when attempting to rotate a token that has no associated
     * tokenable model, which is required to perform the rotation operation.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function forRotation(): self
    {
        return new self('Token has no associated tokenable model');
    }

    /**
     * Create an exception for a parent token without a tokenable model.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function forParentToken(): self
    {
        return new self('Parent token has no tokenable model');
    }
}
