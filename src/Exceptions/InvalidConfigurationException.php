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
 * Exception thrown when the package encounters invalid or missing configuration.
 *
 * Configuration errors can prevent the package from functioning correctly. This
 * exception occurs when required configuration values are missing or when
 * configuration values reference components that do not exist in the system.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidConfigurationException extends RuntimeException
{
    /**
     * Create an exception for a missing token type configuration.
     *
     * This occurs when a token type is referenced but does not have a
     * corresponding entry in the token types configuration array.
     *
     * @param  string $type The missing token type identifier
     * @return self   Exception instance with descriptive error message
     */
    public static function missingTokenType(string $type): self
    {
        return new self(sprintf("Token type '%s' is not configured. Add it to the 'token_types' configuration.", $type));
    }

    /**
     * Create an exception for a missing audit driver configuration.
     *
     * This occurs when an audit driver is referenced but does not have a
     * corresponding entry in the audit drivers configuration array.
     *
     * @param  string $driver The missing audit driver identifier
     * @return self   Exception instance with descriptive error message
     */
    public static function missingAuditDriver(string $driver): self
    {
        return new self(sprintf("Audit driver '%s' is not configured. Add it to the 'audit_drivers' configuration.", $driver));
    }

    /**
     * Create an exception for an invalid morph type configuration.
     *
     * This occurs when a polymorphic relationship morph type is configured
     * with an invalid value or references a class that does not exist.
     *
     * @param  string $type The invalid morph type value
     * @return self   Exception instance with descriptive error message
     */
    public static function invalidMorphType(string $type): self
    {
        return new self(sprintf("Invalid morph type '%s'. Ensure the class exists and is properly configured.", $type));
    }

    /**
     * Create an exception for a missing or empty name field.
     *
     * This occurs when a token type configuration does not include
     * a valid name field.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function missingName(): self
    {
        return new self('Token type configuration must include a non-empty "name" field.');
    }

    /**
     * Create an exception for a missing or empty prefix field.
     *
     * This occurs when a token type configuration does not include
     * a valid prefix field.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function missingPrefix(): self
    {
        return new self('Token type configuration must include a non-empty "prefix" field.');
    }

    /**
     * Create an exception for invalid abilities field type.
     *
     * This occurs when a token type configuration has an abilities
     * field that is not an array.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function invalidAbilitiesType(): self
    {
        return new self('Token type "abilities" must be an array.');
    }

    /**
     * Create an exception for invalid expiration field type.
     *
     * This occurs when a token type configuration has an expiration
     * field that is not a positive integer or null.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function invalidExpirationType(): self
    {
        return new self('Token type "expiration" must be a positive integer or null.');
    }

    /**
     * Create an exception for invalid rate limit field type.
     *
     * This occurs when a token type configuration has a rate_limit
     * field that is not a positive integer or null.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function invalidRateLimitType(): self
    {
        return new self('Token type "rate_limit" must be a positive integer or null.');
    }

    /**
     * Create an exception for invalid environments field type.
     *
     * This occurs when a token type configuration has an environments
     * field that is not an array.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function invalidEnvironmentsType(): self
    {
        return new self('Token type "environments" must be an array.');
    }

    /**
     * Create an exception for invalid server_side_only field type.
     *
     * This occurs when a token type configuration has a server_side_only
     * field that is not a boolean.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function invalidServerSideOnlyType(): self
    {
        return new self('Token type "server_side_only" must be a boolean.');
    }
}
