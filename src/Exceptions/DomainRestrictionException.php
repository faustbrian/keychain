<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

use function implode;
use function sprintf;

/**
 * Exception thrown when a token is used from a disallowed domain.
 *
 * Domain restrictions limit token usage to specific domains or subdomains,
 * providing an additional security layer for web-based API access. This
 * exception occurs when a request originates from a domain that is not
 * included in the token's allowed domains list.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class DomainRestrictionException extends RuntimeException
{
    /**
     * Create an exception for a disallowed domain.
     *
     * This occurs when the request's origin domain does not match any of
     * the domains explicitly permitted by the token's configuration.
     *
     * @param  string        $domain         The domain that attempted to use the token
     * @param  array<string> $allowedDomains List of permitted domains for this token
     * @return self          Exception instance with descriptive error message
     */
    public static function notAllowed(string $domain, array $allowedDomains): self
    {
        $allowedList = implode(', ', $allowedDomains);

        return new self(sprintf("Domain '%s' is not allowed. Allowed domains: %s", $domain, $allowedList));
    }

    /**
     * Create an exception when origin/referer headers are missing.
     *
     * This occurs when domain validation is required but no origin
     * or referer header is present in the request.
     *
     * @return self Exception instance with descriptive error message
     */
    public static function missingHeader(): self
    {
        return new self('No origin or referer header present for domain validation.');
    }

    /**
     * Create an exception for a disallowed domain without listing allowed domains.
     *
     * This occurs when the request's origin domain is not permitted
     * by the token's configuration.
     *
     * @param  string $domain The domain that attempted to use the token
     * @return self   Exception instance with descriptive error message
     */
    public static function forDomain(string $domain): self
    {
        return new self(sprintf('Domain %s is not allowed for this token.', $domain));
    }
}
