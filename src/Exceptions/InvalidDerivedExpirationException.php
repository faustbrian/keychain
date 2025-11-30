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
 * Exception thrown when derived token expiration exceeds parent token expiration.
 *
 * Token derivation enforces that child tokens cannot have a longer lifespan than
 * their parent tokens. This exception occurs when attempting to create a derived
 * token with an expiration date that extends beyond the parent's expiration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidDerivedExpirationException extends RuntimeException
{
    /**
     * Create an exception for an expiration that exceeds the parent's expiration.
     *
     * @param  DateTimeInterface $childExpiration  The expiration requested for the child token
     * @param  DateTimeInterface $parentExpiration The expiration of the parent token
     * @return self              Exception instance with descriptive error message
     */
    public static function create(DateTimeInterface $childExpiration, DateTimeInterface $parentExpiration): self
    {
        return new self(
            'Derived token expiration ['.$childExpiration->format('Y-m-d H:i:s').'] '.
            'cannot exceed parent token expiration ['.$parentExpiration->format('Y-m-d H:i:s').'].',
        );
    }
}
