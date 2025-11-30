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
 * Exception thrown when an invalid or unregistered token type is encountered.
 *
 * Token types define the behavior and characteristics of tokens in the system.
 * This exception occurs when attempting to use a token type that either does
 * not exist in the system or has not been properly registered in the configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidTokenTypeException extends RuntimeException
{
    /**
     * Create an exception for an unknown token type.
     *
     * This occurs when code references a token type that does not exist
     * in the system's token type definitions.
     *
     * @param  string $type The unknown token type identifier
     * @return self   Exception instance with descriptive error message
     */
    public static function unknown(string $type): self
    {
        return new self('Unknown token type: '.$type);
    }

    /**
     * Create an exception for a token type that has not been registered.
     *
     * This occurs when a token type exists conceptually but has not been
     * properly configured in the token types configuration array.
     *
     * @param  string $type The unregistered token type identifier
     * @return self   Exception instance with descriptive error message
     */
    public static function notRegistered(string $type): self
    {
        return new self(sprintf("Token type '%s' is not registered in the configuration.", $type));
    }

    /**
     * Create an exception when a token type is not allowed for a request.
     *
     * This occurs when middleware validates that the current token's type
     * is not among the allowed types for an endpoint.
     *
     * @param  string        $currentType  The actual token type from the request
     * @param  array<string> $allowedTypes List of allowed token types
     * @return self          Exception instance with descriptive error message
     */
    public static function notAllowedForRequest(string $currentType, array $allowedTypes): self
    {
        $allowedList = implode(', ', $allowedTypes);

        return new self(sprintf("Token type '%s' is not allowed. Allowed types: %s", $currentType, $allowedList));
    }
}
