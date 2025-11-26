<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\TokenGenerators;

use Cline\Keychain\Contracts\TokenGenerator;
use Cline\Keychain\Support\TokenComponents;

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
     * Base58 alphabet (no 0OIl characters).
     */
    private const string BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /**
     * Length of the random secret portion.
     */
    private const int SECRET_LENGTH = 24;

    /**
     * {@inheritDoc}
     */
    public function generate(string $prefix, string $environment): string
    {
        $secret = $this->generateBase58String(self::SECRET_LENGTH);

        return sprintf('%s_%s_%s', $prefix, $environment, $secret);
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $plainToken, string $hashedToken): bool
    {
        return hash_equals($hashedToken, $this->hash($plainToken));
    }

    /**
     * Generate a random base58 string of the specified length.
     *
     * @param  int    $length Desired length of the output string
     * @return string Random base58-encoded string
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
