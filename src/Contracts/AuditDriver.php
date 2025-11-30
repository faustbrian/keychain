<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Collection;

/**
 * Contract for audit logging drivers.
 *
 * Audit drivers provide pluggable storage backends for token activity logging,
 * enabling compliance, security monitoring, and debugging capabilities. Different
 * implementations can store audit data in databases, log files, external services,
 * or specialized audit platforms.
 *
 * Audit logging captures critical token lifecycle events:
 * - Creation and initial assignment
 * - Authentication attempts (successful and failed)
 * - Permission checks and denials
 * - Token rotation and renewal
 * - Revocation and deletion
 * - Suspicious activity patterns
 *
 * Use cases include:
 * - Compliance requirements (SOC 2, GDPR, HIPAA)
 * - Security incident investigation
 * - Usage analytics and reporting
 * - Anomaly detection and alerting
 * - Debugging authentication issues
 *
 * ```php
 * class DatabaseAuditDriver implements AuditDriver
 * {
 *     public function log(AccessToken $token, AuditEvent $event, array $context = []): void
 *     {
 *         AccessTokenAuditLog::create([
 *             'token_id' => $token->id,
 *             'event_type' => $event->type(),
 *             'event_data' => $event->data(),
 *             'context' => $context,
 *             'ip_address' => request()->ip(),
 *             'user_agent' => request()->userAgent(),
 *         ]);
 *     }
 *
 *     public function getLogsForToken(AccessToken $token): Collection
 *     {
 *         return AccessTokenAuditLog::where('token_id', $token->id)
 *             ->orderBy('created_at', 'desc')
 *             ->get();
 *     }
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface AuditDriver
{
    /**
     * Log an audit event for a token.
     *
     * Records a significant event in the token's lifecycle or usage history.
     * The event contains structured information about what occurred, while
     * the context array provides additional request-specific or environmental
     * data.
     *
     * Implementations should:
     * - Store events durably and reliably
     * - Include timestamps automatically
     * - Capture request metadata (IP, user agent) when available
     * - Handle failures gracefully without breaking the main flow
     *
     * The context array might include:
     * - ip_address: Client IP address
     * - user_agent: HTTP user agent
     * - request_id: Unique request identifier
     * - resource: Resource being accessed
     * - action: Specific action attempted
     *
     * @param AccessToken          $token   The token this event relates to
     * @param AuditEvent           $event   The event being logged
     * @param array<string, mixed> $context Additional contextual information
     */
    public function log(AccessToken $token, AuditEvent $event, array $context = []): void;

    /**
     * Retrieve all audit logs for a specific token.
     *
     * Returns a collection of audit events associated with the given token,
     * typically ordered chronologically (newest first) for easy review. This
     * enables investigation of token usage history, security reviews, and
     * compliance audits.
     *
     * Implementations may:
     * - Apply pagination for large log sets
     * - Filter by date ranges if requested
     * - Include related data (user info, IP geolocation)
     * - Aggregate or summarize events
     *
     * @param  AccessToken            $token The token to retrieve logs for
     * @return Collection<int, mixed> Collection of audit log entries for this token
     */
    public function getLogsForToken(AccessToken $token): Collection;
}
