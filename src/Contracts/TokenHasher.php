<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

/**
 * Contract for token hashing implementations.
 *
 * Token hashers provide cryptographically secure one-way hashing of API tokens
 * for safe database storage. Since tokens are essentially passwords, they must
 * never be stored in plain text. This contract enables pluggable hash algorithms
 * while maintaining a consistent interface for token security.
 *
 * Critical security requirements:
 * - Hash algorithms must be cryptographically secure (SHA-256+ or bcrypt family)
 * - Verification must use timing-safe comparison to prevent timing attacks
 * - Hash output must be deterministic for the same input
 * - No hash collisions for practical token lengths
 *
 * Common implementations:
 * - SHA-256: Fast, deterministic, suitable for high-throughput APIs
 * - SHA-512: Higher security margin, minimal performance cost
 * - Bcrypt/Argon2: Adaptive cost, resistant to brute-force attacks
 *
 * ```php
 * class Sha256TokenHasher implements TokenHasher
 * {
 *     public function hash(string $token): string
 *     {
 *         return hash('sha256', $token);
 *     }
 *
 *     public function verify(string $token, string $hash): bool
 *     {
 *         return hash_equals($this->hash($token), $hash);
 *     }
 * }
 *
 * // Usage
 * $hasher = new Sha256TokenHasher();
 *
 * // At token creation
 * $plainToken = 'usr_prod_abc123...';
 * $hashedToken = $hasher->hash($plainToken);
 * // Store $hashedToken in database, show $plainToken once to user
 *
 * // During authentication
 * if ($hasher->verify($providedToken, $storedHash)) {
 *     // Token is valid, authenticate user
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface TokenHasher
{
    /**
     * Hash a plain-text token for secure storage.
     *
     * Generates a cryptographically secure one-way hash of the token that can
     * be safely stored in the database. The same token input must always produce
     * the same hash output for verification to work correctly.
     *
     * Security considerations:
     * - Never store the plain-text token; only store the hash
     * - Hash should be irreversible (one-way function)
     * - Must use cryptographically secure algorithms
     * - Should be fast enough for high-throughput authentication
     *
     * The plain-text token should only be shown to the user once at creation
     * time and never logged or persisted.
     *
     * @param  string $token The plain-text token to hash
     * @return string The hashed token in hexadecimal or base64 format, suitable for database storage
     */
    public function hash(string $token): string;

    /**
     * Verify a plain-text token against a stored hash.
     *
     * Compares the provided plain-text token with a stored hashed version to
     * determine if they match. This is the core of token authentication, called
     * on every API request to validate the presented credentials.
     *
     * CRITICAL: Implementations MUST use timing-safe comparison (e.g., hash_equals()
     * in PHP) to prevent timing attacks that could leak information about the hash
     * or enable brute-force optimization.
     *
     * The method should:
     * - Hash the plain-text token using the same algorithm
     * - Compare with the stored hash using constant-time comparison
     * - Return false for any errors or mismatches
     * - Not throw exceptions (return false instead)
     *
     * @param  string $token The plain-text token to verify
     * @param  string $hash  The stored hash to verify against
     * @return bool   True if the token matches the hash, false otherwise
     */
    public function verify(string $token, string $hash): bool;
}
