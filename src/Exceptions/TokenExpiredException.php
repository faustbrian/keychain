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
 * Exception thrown when attempting to use an expired token.
 *
 * Tokens can have expiration timestamps to enforce time-based access control.
 * This exception occurs when a token is used after its expiration date has
 * passed, preventing unauthorized continued access.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenExpiredException extends RuntimeException
{
    /**
     * Create an exception for a token that expired at a specific time.
     *
     * This occurs when the current timestamp exceeds the token's expiration
     * timestamp, indicating that the token's validity period has ended.
     *
     * @param  DateTimeInterface $expiredAt The timestamp when the token expired
     * @return self              Exception instance with descriptive error message
     */
    public static function at(DateTimeInterface $expiredAt): self
    {
        return new self('Token expired at '.$expiredAt->format('Y-m-d H:i:s'));
    }

    /**
     * Create an exception for an expired token without timestamp details.
     *
     * This occurs when a token has expired but the exact expiration
     * time is not needed in the error message.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function expired(): self
    {
        return new self('This token has expired.');
    }
}
