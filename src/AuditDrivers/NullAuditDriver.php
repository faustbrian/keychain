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
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Collection;

use function collect;

/**
 * Null audit driver that performs no logging operations.
 *
 * This driver provides a no-op implementation of the AuditDriver contract,
 * useful for testing, development, or production environments where audit
 * logging is not required or would create unnecessary overhead.
 *
 * Use cases:
 * - Testing environments where audit logs are not needed
 * - Performance-critical applications that don't require audit trails
 * - Development setups to reduce database writes
 * - Temporary disabling of audit logging without code changes
 * - Mock implementations in unit tests
 *
 * Example usage:
 * ```php
 * // In config/bearer.php
 * 'audit' => [
 *     'driver' => 'null',
 * ],
 *
 * // Or programmatically
 * $driver = new NullAuditDriver();
 * $driver->log($token, AuditEvent::Authenticated); // Does nothing
 * $logs = $driver->getLogsForToken($token); // Returns empty collection
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NullAuditDriver implements AuditDriver
{
    /**
     * Log an audit event for a token.
     *
     * This is a no-op implementation that does nothing.
     *
     * @param AccessToken          $token   The token this event relates to
     * @param AuditEvent           $event   The event being logged
     * @param array<string, mixed> $context Additional contextual information
     */
    public function log(AccessToken $token, AuditEvent $event, array $context = []): void
    {
        // Intentionally empty - no logging performed
    }

    /**
     * Retrieve all audit logs for a specific token.
     *
     * Always returns an empty collection since this driver doesn't store logs.
     *
     * @param  AccessToken            $token The token to retrieve logs for
     * @return Collection<int, mixed> Empty collection
     */
    public function getLogsForToken(AccessToken $token): Collection
    {
        return collect();
    }
}
