<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

use Cline\Bearer\Support\TokenComponents;

/**
 * Contract for token generation and validation strategies.
 *
 * Token generators encapsulate the logic for creating, parsing, hashing, and
 * verifying access tokens. This abstraction enables different token formats and
 * security strategies while maintaining a consistent interface.
 *
 * Token generation typically involves:
 * - Creating cryptographically secure random tokens
 * - Adding prefixes and environment markers for identification
 * - Hashing tokens for secure storage
 * - Parsing and extracting token components
 * - Verifying plain tokens against hashed versions
 *
 * Different implementations might use:
 * - Random bytes with prefixes (default)
 * - JWT-style signed tokens
 * - Time-based tokens with embedded expiration
 * - Macaroon-style tokens with embedded capabilities
 *
 * ```php
 * $generator = new DefaultTokenGenerator();
 *
 * // Generate a new token
 * $plainToken = $generator->generate('usr', 'production');
 * // Returns: "usr_prod_abc123def456..."
 *
 * // Hash for storage
 * $hashedToken = $generator->hash($plainToken);
 *
 * // Later: verify a token
 * if ($generator->verify($plainToken, $hashedToken)) {
 *     // Token is valid
 * }
 *
 * // Parse token components
 * $components = $generator->parse($plainToken);
 * echo $components->prefix;      // "usr"
 * echo $components->environment; // "production"
 * echo $components->secret;      // "abc123def456..."
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface TokenGenerator
{
    /**
     * Generate a new token with the given prefix and environment.
     *
     * Creates a cryptographically secure token string that includes the
     * specified prefix and environment marker. The token should be suitable
     * for use as an API credential and must be unique.
     *
     * Generated tokens are returned in plain text form and should only be
     * shown to the user once at creation time. The hashed version should be
     * stored in the database.
     *
     * @param  string $prefix      Token type prefix (e.g., 'usr', 'svc', 'tmp')
     * @param  string $environment Environment marker (e.g., 'production', 'staging', 'local')
     * @return string The generated plain-text token (e.g., 'usr_prod_abc123...')
     */
    public function generate(string $prefix, string $environment): string;

    /**
     * Parse a token string into its component parts.
     *
     * Extracts the prefix, environment, and secret portions from a token
     * string. This is useful for validating token format and extracting
     * metadata before verification.
     *
     * Returns null if the token format is invalid or cannot be parsed.
     *
     * @param  string               $token The plain-text token to parse
     * @return null|TokenComponents Parsed components, or null if invalid format
     */
    public function parse(string $token): ?TokenComponents;

    /**
     * Create a hash of the token for secure storage.
     *
     * Generates a one-way hash of the token that can be safely stored in the
     * database. The hashing algorithm should be cryptographically secure
     * (e.g., SHA-256, bcrypt) and consistent to enable verification.
     *
     * Only hashed tokens should be persisted; never store plain-text tokens.
     *
     * @param  string $token The plain-text token to hash
     * @return string The hashed token suitable for database storage
     */
    public function hash(string $token): string;

    /**
     * Verify a plain-text token against a hashed token.
     *
     * Compares the provided plain-text token with a stored hashed version
     * to determine if they match. This is used during authentication to
     * validate that the presented token is legitimate.
     *
     * The verification must be timing-safe to prevent timing attacks that
     * could leak information about the token structure.
     *
     * @param  string $plainToken  The plain-text token to verify
     * @param  string $hashedToken The hashed token from storage
     * @return bool   True if the tokens match, false otherwise
     */
    public function verify(string $plainToken, string $hashedToken): bool;
}
