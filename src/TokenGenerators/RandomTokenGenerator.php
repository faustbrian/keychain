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
use function mb_strlen;
use function sprintf;

/**
 * Sanctum-style random token generator with CRC32 checksum.
 *
 * Generates tokens in the format: {prefix}_{env}_{random40}{crc32}
 * Example: sk_test_EXAMPLE1234567890abcdefgKpQ6yTdWaXcZ1b92a8f4e3c
 *
 * Uses Laravel's Str::random() for 40 character entropy, appended with
 * an 8 character CRC32 checksum for additional integrity verification.
 * This mirrors Laravel Sanctum's token generation approach.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class RandomTokenGenerator implements TokenGenerator
{
    /**
     * Length of the random entropy portion in characters.
     */
    private const int ENTROPY_LENGTH = 40;

    /**
     * Generate a new random token with CRC32 checksum.
     *
     * Creates a token in the format: {prefix}_{environment}_{random40}{crc32}
     * The 40-character random portion provides high entropy, while the 8-character
     * CRC32 checksum allows for basic integrity verification.
     *
     * @param  string $prefix      Token type prefix (e.g., 'sk', 'pk', 'rk')
     * @param  string $environment Environment marker (e.g., 'production', 'test')
     * @return string The complete generated token string
     */
    public function generate(string $prefix, string $environment): string
    {
        $entropy = Str::random(self::ENTROPY_LENGTH);
        $checksum = hash('crc32b', $entropy);
        $secret = $entropy.$checksum;

        return sprintf('%s_%s_%s', $prefix, $environment, $secret);
    }

    /**
     * Parse a token string into its component parts.
     *
     * Validates the token structure and extracts the prefix, environment, and
     * secret portions. Returns null if the token format is invalid or the secret
     * length doesn't match the expected 48 characters (40 entropy + 8 checksum).
     *
     * @param  string               $token The complete token string to parse
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

        // Validate secret length (40 chars entropy + 8 chars checksum)
        if (mb_strlen($secret) !== self::ENTROPY_LENGTH + 8) {
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
     * Generates a cryptographic hash suitable for secure storage in the database.
     * The full token string is hashed to prevent exposure of the plaintext token.
     *
     * @param  string $token The plaintext token to hash
     * @return string The SHA-256 hash of the token
     */
    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * Verify a plaintext token against a stored hash.
     *
     * Uses timing-safe comparison to prevent timing attacks during verification.
     * This ensures constant-time comparison regardless of where the hash differs.
     *
     * @param  string $plainToken  The plaintext token to verify
     * @param  string $hashedToken The stored hash to compare against
     * @return bool   True if the token matches the hash, false otherwise
     */
    public function verify(string $plainToken, string $hashedToken): bool
    {
        return hash_equals($hashedToken, $this->hash($plainToken));
    }
}
