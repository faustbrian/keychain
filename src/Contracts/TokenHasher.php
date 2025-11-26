<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Contracts;

/**
 * Contract for token hashing implementations.
 *
 * Implementations of this interface are responsible for hashing plain-text
 * tokens for secure storage and verifying tokens against stored hashes.
 * This enables pluggable hash algorithm support.
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface TokenHasher
{
    /**
     * Hash a plain-text token for storage.
     *
     * @param  string $token The plain-text token to hash
     * @return string The hashed token suitable for database storage
     */
    public function hash(string $token): string;

    /**
     * Verify a plain-text token against a stored hash.
     *
     * @param  string $token The plain-text token to verify
     * @param  string $hash  The stored hash to verify against
     * @return bool   True if the token matches the hash, false otherwise
     */
    public function verify(string $token, string $hash): bool;
}
