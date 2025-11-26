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
     * Length of the random entropy portion.
     */
    private const int ENTROPY_LENGTH = 40;

    /**
     * {@inheritDoc}
     */
    public function generate(string $prefix, string $environment): string
    {
        $entropy = Str::random(self::ENTROPY_LENGTH);
        $checksum = hash('crc32b', $entropy);
        $secret = $entropy.$checksum;

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
}
