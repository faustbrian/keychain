<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Enums;

/**
 * Defines audit log event types for token lifecycle tracking.
 *
 * This enum represents all significant events in a token's lifecycle that
 * should be recorded in audit logs for security, compliance, and debugging
 * purposes.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum AuditEvent: string
{
    /**
     * Token was created.
     *
     * Logged when a new token is generated and stored.
     */
    case Created = 'created';

    /**
     * Token was successfully authenticated.
     *
     * Logged when a token passes authentication and is used to access
     * protected resources.
     */
    case Authenticated = 'authenticated';

    /**
     * Token was revoked.
     *
     * Logged when a token is explicitly revoked and invalidated.
     */
    case Revoked = 'revoked';

    /**
     * Token was rotated.
     *
     * Logged when a token is replaced with a new one as part of rotation.
     */
    case Rotated = 'rotated';

    /**
     * Authentication failed.
     *
     * Logged when a token fails authentication due to invalid credentials,
     * signature mismatch, or other validation failures.
     */
    case Failed = 'failed';

    /**
     * Request was rate limited.
     *
     * Logged when a token's usage exceeds configured rate limits.
     */
    case RateLimited = 'rate_limited';

    /**
     * IP address was blocked.
     *
     * Logged when a request from a blocked IP address is denied.
     */
    case IpBlocked = 'ip_blocked';

    /**
     * Domain was blocked.
     *
     * Logged when a request from a blocked domain is denied.
     */
    case DomainBlocked = 'domain_blocked';

    /**
     * Token expired.
     *
     * Logged when an expired token is used and rejected.
     */
    case Expired = 'expired';

    /**
     * Token was derived from a parent token.
     *
     * Logged when a child token is created from a parent token in a
     * hierarchical derivation relationship.
     */
    case Derived = 'derived';
}
