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
     * {@inheritDoc}
     */
    public function generate(string $prefix, string $environment): string
    {
        $uuid = (string) Str::uuid();

        return sprintf('%s_%s_%s', $prefix, $environment, $uuid);
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
