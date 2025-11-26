<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Support;

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
     * @param string $prefix      Token type prefix (e.g., 'usr', 'svc', 'tmp')
     * @param string $environment Environment marker (e.g., 'production', 'staging', 'local')
     * @param string $secret      The secret/random portion of the token
     * @param string $fullToken   The complete token string
     */
    public function __construct(
        public string $prefix,
        public string $environment,
        public string $secret,
        public string $fullToken,
    ) {}
}
