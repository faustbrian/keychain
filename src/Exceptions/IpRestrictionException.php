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
 * Exception thrown when a token is used from a disallowed IP address.
 *
 * IP restrictions limit token usage to specific IP addresses or CIDR ranges,
 * providing network-level access control for API tokens. This exception occurs
 * when a request originates from an IP address that is not included in the
 * token's allowed IPs list.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class IpRestrictionException extends RuntimeException
{
    /**
     * Create an exception for a disallowed IP address.
     *
     * This occurs when the request's source IP address does not match any of
     * the IP addresses or CIDR ranges explicitly permitted by the token's
     * configuration.
     *
     * @param  string        $ip         The IP address that attempted to use the token
     * @param  array<string> $allowedIps List of permitted IP addresses/ranges for this token
     * @return self          Exception instance with descriptive error message
     */
    public static function notAllowed(string $ip, array $allowedIps): self
    {
        $allowedList = implode(', ', $allowedIps);

        return new self(sprintf("IP address '%s' is not allowed. Allowed IPs: %s", $ip, $allowedList));
    }

    /**
     * Create an exception for a disallowed IP address without listing allowed IPs.
     *
     * This occurs when the request's source IP address is not permitted
     * by the token's configuration.
     *
     * @param  string $ip The IP address that attempted to use the token
     * @return self   Exception instance with descriptive error message
     */
    public static function forIp(string $ip): self
    {
        return new self(sprintf('IP address %s is not allowed for this token.', $ip));
    }
}
