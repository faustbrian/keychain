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

use function count;
use function explode;
use function hash;
use function hash_equals;
use function mb_strlen;
use function random_int;
use function sprintf;

/**
 * Stripe/Seam-style token generator using base58 encoding.
 *
 * Generates tokens in the format: {prefix}_{env}_{base58random}
 * Example: sk_test_EXAMPLE1234567890abcdef
 *
 * Uses base58 alphabet (excludes 0, O, I, l to avoid confusion) with 24
 * character random parts for high entropy while maintaining readability.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class SeamTokenGenerator implements TokenGenerator
{
    /**
     * Base58 alphabet excluding ambiguous characters (0, O, I, l).
     *
     * This alphabet ensures tokens remain readable and reduces transcription errors
     * by eliminating characters that look similar in most fonts.
     */
    private const string BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /**
     * Length of the random secret portion in characters.
     */
    private const int SECRET_LENGTH = 24;

    /**
     * Generate a new base58-encoded token.
     *
     * Creates a token in the format: {prefix}_{environment}_{base58random}
     * The base58 encoding ensures tokens are URL-safe and easily transcribable
     * while maintaining high entropy through 24 random characters.
     *
     * @param  string $prefix      Token type prefix (e.g., 'sk', 'pk', 'rk')
     * @param  string $environment Environment marker (e.g., 'production', 'test')
     * @return string The complete generated token string
     */
    public function generate(string $prefix, string $environment): string
    {
        $secret = $this->generateBase58String(self::SECRET_LENGTH);

        return sprintf('%s_%s_%s', $prefix, $environment, $secret);
    }

    /**
     * Parse a token string into its component parts.
     *
     * Validates the token structure and extracts the prefix, environment, and
     * secret portions. Returns null if the token format is invalid (not exactly
     * 3 underscore-separated parts or if any part is empty).
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

    /**
     * Generate a cryptographically secure random base58 string.
     *
     * Uses random_int() for cryptographic randomness and selects characters from
     * the base58 alphabet to build a string of the specified length. Each character
     * is independently selected with uniform distribution.
     *
     * @param  int    $length Desired length of the output string in characters
     * @return string Cryptographically random base58-encoded string
     */
    private function generateBase58String(int $length): string
    {
        $alphabetLength = mb_strlen(self::BASE58_ALPHABET);
        $result = '';

        for ($i = 0; $i < $length; ++$i) {
            $randomIndex = random_int(0, $alphabetLength - 1);
            $result .= self::BASE58_ALPHABET[$randomIndex];
        }

        return $result;
    }
}
