<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenGenerators;

use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Support\TokenComponents;
use Illuminate\Support\Str;

use function count;
use function explode;
use function hash;
use function hash_equals;
use function sprintf;

/**
 * UUID-based token generator.
 *
 * Generates tokens in the format: {prefix}_{env}_{uuid}
 * Example: sk_test_550e8400-e29b-41d4-a716-446655440000
 *
 * Uses Laravel's Str::uuid() method to generate version 4 UUIDs,
 * providing a standardized format that is widely recognized and
 * easily validated.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class UuidTokenGenerator implements TokenGenerator
{
    /**
     * Generate a new token with UUID as the secret component.
     *
     * Creates a token in the format: {prefix}_{environment}_{uuid}
     * The UUID is generated using Laravel's Str::uuid() method, which
     * produces a version 4 (random) UUID.
     *
     * @param  string $prefix      Token prefix indicating the type (e.g., 'sk', 'pk')
     * @param  string $environment Environment identifier (e.g., 'test', 'live')
     * @return string The generated token with UUID component
     */
    public function generate(string $prefix, string $environment): string
    {
        $uuid = (string) Str::uuid();

        return sprintf('%s_%s_%s', $prefix, $environment, $uuid);
    }

    /**
     * Parse a token string into its constituent components.
     *
     * Validates the token structure and ensures the secret portion is a valid
     * UUID. Returns null if the token format is invalid or the secret is not
     * a properly formatted UUID.
     *
     * Expected format: {prefix}_{environment}_{uuid}
     *
     * @param  string               $token The token string to parse
     * @return null|TokenComponents Parsed token components, or null if invalid
     */
    public function parse(string $token): ?TokenComponents
    {
        $parts = explode('_', $token);

        if (count($parts) !== 3) {
            return null;
        }

        [$prefix, $environment, $secret] = $parts;

        if ($prefix === '' || $prefix === '0' || ($environment === '' || $environment === '0') || ($secret === '' || $secret === '0')) {
            return null;
        }

        // Validate UUID format
        if (!Str::isUuid($secret)) {
            return null;
        }

        return new TokenComponents(
            prefix: $prefix,
            environment: $environment,
            secret: $secret,
            fullToken: $token,
        );
    }

    /**
     * Hash a token using SHA-256.
     *
     * Produces a 64-character hexadecimal hash suitable for secure database
     * storage. The original token should never be stored in plain text.
     *
     * @param  string $token The plain token to hash
     * @return string SHA-256 hash of the token
     */
    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Verify a plain token against its hashed version.
     *
     * Uses timing-safe comparison to prevent timing attacks. Hashes the plain
     * token and compares it against the stored hash.
     *
     * @param  string $plainToken  The plain token to verify
     * @param  string $hashedToken The stored hash to compare against
     * @return bool   True if the tokens match, false otherwise
     */
    public function verify(string $plainToken, string $hashedToken): bool
    {
        return hash_equals($hashedToken, $this->hash($plainToken));
    }
}
