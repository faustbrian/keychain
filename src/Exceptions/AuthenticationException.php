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
 * Exception thrown when authentication fails or is not present.
 *
 * This exception occurs when a protected endpoint is accessed without valid
 * authentication credentials or when the authentication token is missing.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AuthenticationException extends RuntimeException
{
    /**
     * Create an exception for unauthenticated access.
     *
     * This occurs when a request is made without valid authentication
     * credentials or when no access token is present.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function unauthenticated(): self
    {
        return new self('Unauthenticated.');
    }
}
