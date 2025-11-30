<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use Cline\Bearer\Database\Models\AccessToken;
use RuntimeException;

/**
 * Exception thrown when attempting to derive a token from a parent that cannot derive.
 *
 * Token derivation is restricted based on several factors including the parent's
 * validity status, current depth in the hierarchy, and configured depth limits.
 * This exception occurs when derivation is attempted but the parent token doesn't
 * meet the requirements.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CannotDeriveTokenException extends RuntimeException
{
    /**
     * Create an exception for a parent token that cannot derive children.
     *
     * @param  AccessToken $parentToken The token that cannot derive children
     * @return self        Exception instance with descriptive error message
     */
    public static function fromParentToken(AccessToken $parentToken): self
    {
        $reason = match (true) {
            $parentToken->isRevoked() => 'The parent token has been revoked',
            $parentToken->isExpired() => 'The parent token has expired',
            default => 'The parent token has reached maximum derivation depth',
        };

        return new self($reason.' and cannot derive child tokens.');
    }
}
