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
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Spatie\Activitylog\Models\Activity;

use function activity;
use function request;

/**
 * Audit driver using Spatie's Laravel Activity Log package.
 *
 * Integrates token audit logging with the popular spatie/laravel-activitylog
 * package, enabling unified activity tracking across your application. This
 * driver is ideal when you're already using Spatie's activity log for other
 * models and want consistent logging infrastructure.
 *
 * Features:
 * - Unified activity log interface across all models
 * - Rich query capabilities from Spatie's Activity model
 * - Support for causer tracking (who performed the action)
 * - Custom log names for filtering and organization
 * - Properties and metadata support
 *
 * Requirements:
 * - spatie/laravel-activitylog package installed
 * - Activity log migrations run
 *
 * Example usage:
 * ```php
 * $driver = new SpatieActivityLogDriver('api-tokens');
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
 *
 * @psalm-immutable
 */
final readonly class SpatieActivityLogDriver implements AuditDriver
{
    /**
     * Create a new Spatie Activity Log driver instance.
     *
     * @param string $logName The log name to use for activity entries in Spatie's
     *                        activity_log table. This allows filtering and organizing
     *                        token audit events separately from other application
     *                        activities. Defaults to 'bearer' for consistent
     *                        namespace isolation.
     */
    public function __construct(
        private string $logName = 'bearer',
    ) {}

    /**
     * Log an audit event for a token.
     *
     * Creates an activity log entry using Spatie's activity() helper, recording
     * the token as the subject, the tokenable (owner) as the causer, and capturing
     * request metadata in properties.
     *
     * @param AccessToken          $token   The token this event relates to
     * @param AuditEvent           $event   The event being logged
     * @param array<string, mixed> $context Additional contextual information
     */
    public function log(AccessToken $token, AuditEvent $event, array $context = []): void
    {
        activity($this->logName)
            ->performedOn($token)
            ->causedBy($token->tokenable)
            ->event($event->value)
            ->withProperties([
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
                ...$context,
            ])
            ->log('Token '.$event->value);
    }

    /**
     * Retrieve all audit logs for a specific token.
     *
     * Queries Spatie's Activity model for all entries related to this token
     * in the configured log name, ordered by creation time (newest first).
     *
     * @param  AccessToken                       $token The token to retrieve logs for
     * @return EloquentCollection<int, Activity> Collection of activity log entries
     */
    public function getLogsForToken(AccessToken $token): EloquentCollection
    {
        /** @var EloquentCollection<int, Activity> $result */
        // @phpstan-ignore-next-line method.notFound (Activity model defines inLog and latest as scopes with @method annotations)
        return Activity::forSubject($token)
            ->inLog($this->logName)
            ->latest()
            ->get();
    }
}
