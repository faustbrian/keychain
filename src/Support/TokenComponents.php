<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Support;

/**
 * Data transfer object for parsed token components.
 *
 * Represents the individual parts of a parsed token string, including the
 * prefix (token type), environment marker, secret portion, and the complete
 * token string. Used by token generators to return structured data when
 * parsing tokens.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenComponents
{
    /**
     * Create a new token components instance.
     *
     * @param string $prefix      Token type prefix that identifies the token's purpose
     *                            (e.g., 'sk' for secret key, 'pk' for public key, 'rk' for
     *                            refresh key). This allows systems to quickly identify and
     *                            categorize tokens without parsing the full string.
     * @param string $environment Environment marker indicating where the token is valid
     *                            (e.g., 'production', 'staging', 'test', 'local'). This prevents
     *                            accidental token use across different environments and aids
     *                            in security by making environment boundaries explicit.
     * @param string $secret      The cryptographically random portion of the token that provides
     *                            uniqueness and entropy. This is the core security element that
     *                            should be stored hashed in the database.
     * @param string $fullToken   The complete reconstructed token string in the format
     *                            {prefix}_{environment}_{secret}. This is what clients receive
     *                            and use for authentication.
     */
    public function __construct(
        public string $prefix,
        public string $environment,
        public string $secret,
        public string $fullToken,
    ) {}
}
