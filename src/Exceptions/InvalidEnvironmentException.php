<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

use function implode;
use function sprintf;

/**
 * Exception thrown when an invalid or disallowed environment is encountered.
 *
 * Environment restrictions limit token usage to specific deployment environments
 * (e.g., production, staging, development). This exception occurs when attempting
 * to use a token in an environment that is either unknown or not permitted by
 * the token's configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidEnvironmentException extends RuntimeException
{
    /**
     * Create an exception for an unknown environment.
     *
     * This occurs when a token references an environment that is not
     * recognized by the system's environment configuration.
     *
     * @param  string $environment The unknown environment identifier
     * @return self   Exception instance with descriptive error message
     */
    public static function unknown(string $environment): self
    {
        return new self('Unknown environment: '.$environment);
    }

    /**
     * Create an exception for a disallowed environment.
     *
     * This occurs when a token is used in a valid environment, but that
     * environment is not included in the token's allowed environments list.
     *
     * @param  string        $environment The current environment identifier
     * @param  array<string> $allowed     List of allowed environment identifiers
     * @return self          Exception instance with descriptive error message
     */
    public static function notAllowed(string $environment, array $allowed): self
    {
        $allowedList = implode(', ', $allowed);

        return new self(sprintf("Environment '%s' is not allowed. Allowed environments: %s", $environment, $allowedList));
    }
}
