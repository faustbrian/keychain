<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\AuditDrivers;

use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Collection;

use function request;

/**
 * Database-backed audit driver using the access_token_audit_logs table.
 *
 * This is the default audit driver that stores token activity logs directly
 * in the application database using the AccessTokenAuditLog model. It provides
 * efficient querying and strong consistency guarantees.
 *
 * Use cases:
 * - Standard applications needing basic audit logging
 * - Compliance requirements that mandate database storage
 * - Fast local queries and reporting
 * - Integration with existing database backup strategies
 *
 * Example usage:
 * ```php
 * $driver = new DatabaseAuditDriver();
 *
 * // Log an event
 * $driver->log($token, AuditEvent::Authenticated, [
 *     'endpoint' => '/api/users',
 *     'method' => 'GET',
 * ]);
 *
 * // Retrieve logs
 * $logs = $driver->getLogsForToken($token);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class DatabaseAuditDriver implements AuditDriver
{
    /**
     * Log an audit event for a token.
     *
     * Creates a new AccessTokenAuditLog entry with the event details, automatically
     * capturing IP address and user agent from the current request context.
     *
     * @param AccessToken          $token   The token this event relates to
     * @param AuditEvent           $event   The event being logged
     * @param array<string, mixed> $context Additional contextual information
     */
    public function log(AccessToken $token, AuditEvent $event, array $context = []): void
    {
        AccessTokenAuditLog::query()->create([
            'token_id' => $token->getKey(),
            'event' => $event,
            'ip_address' => request()->ip(),
            'user_agent' => request()->userAgent(),
            'metadata' => $context,
        ]);
    }

    /**
     * Retrieve all audit logs for a specific token.
     *
     * Returns audit logs ordered by creation time (newest first) for easy
     * review of recent activity.
     *
     * @param  AccessToken                          $token The token to retrieve logs for
     * @return Collection<int, AccessTokenAuditLog> Collection of audit log entries
     */
    public function getLogsForToken(AccessToken $token): Collection
    {
        return $token->auditLogs()->latest('created_at')->get();
    }
}
