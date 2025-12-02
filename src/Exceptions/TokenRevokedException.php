<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use DateTimeInterface;
use RuntimeException;

/**
 * Exception thrown when attempting to use a revoked token.
 *
 * Token revocation allows administrators to invalidate tokens before their
 * expiration date, typically in response to security concerns or access changes.
 * This exception occurs when a token that has been explicitly revoked is used.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenRevokedException extends RuntimeException
{
    /**
     * Create an exception for a token that was revoked at a specific time.
     *
     * This occurs when a token's revocation timestamp exists and has passed,
     * indicating that the token has been explicitly invalidated by an administrator
     * or automated revocation strategy.
     *
     * @param  DateTimeInterface $revokedAt The timestamp when the token was revoked
     * @return self              Exception instance with descriptive error message
     */
    public static function at(DateTimeInterface $revokedAt): self
    {
        return new self('Token was revoked at '.$revokedAt->format('Y-m-d H:i:s'));
    }

    /**
     * Create an exception for a revoked token without timestamp details.
     *
     * This occurs when a token has been revoked but the exact revocation
     * time is not needed in the error message.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function revoked(): self
    {
        return new self('This token has been revoked.');
    }
}
