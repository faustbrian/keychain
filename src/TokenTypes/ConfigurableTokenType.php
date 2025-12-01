<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenTypes;

use Cline\Bearer\Exceptions\InvalidConfigurationException;

use function array_filter;
use function array_key_exists;
use function array_values;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;

/**
 * Configurable token type for user-defined types.
 *
 * Enables applications to define custom token types through configuration
 * without creating dedicated PHP classes. This is useful for application-specific
 * token types that don't warrant a full class implementation.
 *
 * Configuration structure:
 * ```php
 * [
 *     'name' => 'integration',           // Required: Token type name
 *     'prefix' => 'int',                 // Required: Token prefix
 *     'abilities' => ['api:read'],       // Optional: Default abilities (default: ['*'])
 *     'expiration' => 43200,             // Optional: Expiration in minutes (default: null)
 *     'rate_limit' => 500,               // Optional: Requests per minute (default: null)
 *     'environments' => ['production'],  // Optional: Allowed environments (default: ['test', 'live'])
 *     'server_side_only' => true,        // Optional: Server-side restriction (default: false)
 * ]
 * ```
 *
 * Example usage:
 * ```php
 * // Define in config/bearer.php
 * 'token_types' => [
 *     'integration' => [
 *         'name' => 'Integration',
 *         'prefix' => 'int',
 *         'abilities' => ['webhooks:receive', 'api:read'],
 *         'expiration' => 60 * 24 * 90, // 90 days
 *         'rate_limit' => 500,
 *         'server_side_only' => true,
 *     ],
 *     'temporary' => [
 *         'name' => 'Temporary',
 *         'prefix' => 'tmp',
 *         'abilities' => ['upload:file'],
 *         'expiration' => 60, // 1 hour
 *         'rate_limit' => 10,
 *         'environments' => ['test', 'staging', 'production'],
 *     ],
 * ],
 *
 * // Create from config
 * $type = ConfigurableTokenType::fromConfig(config('bearer.token_types.integration'));
 * ```
 *
 * Common use cases:
 * - Integration partner tokens
 * - Temporary access tokens
 * - Testing tokens with specific constraints
 * - Partner/vendor-specific token types
 * - Trial/demo account tokens
 * - Webhook receiver tokens
 *
 * Best practices:
 * - Use descriptive names that indicate purpose
 * - Choose unique prefixes to avoid conflicts
 * - Document custom types in your application
 * - Start with restrictive settings and expand as needed
 * - Consider creating a dedicated class for frequently-used types
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ConfigurableTokenType extends AbstractTokenType
{
    /**
     * Create a configurable token type from configuration array.
     *
     * Validates the configuration and creates a new token type instance
     * with the specified characteristics.
     *
     * @param array<string, mixed> $config Configuration array
     *
     * @throws InvalidConfigurationException If required configuration is missing or invalid
     *
     * @return self New token type instance
     */
    public static function fromConfig(array $config): self
    {
        // Validate required fields
        if (!array_key_exists('name', $config) || !is_string($config['name']) || empty($config['name'])) {
            throw InvalidConfigurationException::missingName();
        }

        if (!array_key_exists('prefix', $config) || !is_string($config['prefix']) || empty($config['prefix'])) {
            throw InvalidConfigurationException::missingPrefix();
        }

        // Extract and validate optional fields
        $abilities = $config['abilities'] ?? ['*'];

        if (!is_array($abilities)) {
            throw InvalidConfigurationException::invalidAbilitiesType();
        }

        $expiration = $config['expiration'] ?? null;

        if ($expiration !== null && (!is_int($expiration) || $expiration < 0)) {
            throw InvalidConfigurationException::invalidExpirationType();
        }

        $rateLimit = $config['rate_limit'] ?? null;

        if ($rateLimit !== null && (!is_int($rateLimit) || $rateLimit < 0)) {
            throw InvalidConfigurationException::invalidRateLimitType();
        }

        $environments = $config['environments'] ?? ['test', 'live'];

        if (!is_array($environments)) {
            throw InvalidConfigurationException::invalidEnvironmentsType();
        }

        $serverSideOnly = $config['server_side_only'] ?? false;

        if (!is_bool($serverSideOnly)) {
            throw InvalidConfigurationException::invalidServerSideOnlyType();
        }

        return new self(
            name: $config['name'],
            prefix: $config['prefix'],
            defaultAbilities: array_values(array_filter($abilities, is_string(...))),
            defaultExpiration: $expiration,
            defaultRateLimit: $rateLimit,
            allowedEnvironments: array_values(array_filter($environments, is_string(...))),
            serverSideOnly: $serverSideOnly,
        );
    }
}
