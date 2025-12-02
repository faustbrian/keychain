# Audit Logging

This guide demonstrates how to use audit logging for token activity.

## Automatic Logging

Bearer automatically logs these events:
- **TokenCreated**: When a new token is issued
- **TokenAuthenticated**: When a token is used to authenticate a request
- **TokenRevoked**: When a token is revoked
- **TokenRotated**: When a token is rotated
- **TokenAuthenticationFailed**: When authentication fails (expired, revoked, IP blocked, etc.)

No manual intervention needed - just use the package normally:

```php
$token = Bearer::for($user)->issue('sk', 'My Token');
// ^ This automatically logs a TokenCreated event
```

## Querying Audit Logs

```php
use Cline\Bearer\Database\Models\TokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;

// Get all audit logs for a token
$logs = $token->accessToken->auditLogs()->get();

// Get logs for specific events
$authLogs = $token->accessToken->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->get();

// Get recent logs
$recentLogs = $token->accessToken->auditLogs()
    ->where('created_at', '>', now()->subDays(7))
    ->latest()
    ->get();

// Get failed authentication attempts
$failedAttempts = TokenAuditLog::query()
    ->whereIn('event', [
        AuditEvent::Failed->value,
        AuditEvent::Expired->value,
        AuditEvent::IpBlocked->value,
        AuditEvent::DomainBlocked->value,
        AuditEvent::RateLimited->value,
    ])
    ->where('created_at', '>', now()->subHours(24))
    ->get();
```

## Audit Log Data

Each audit log contains:

```php
foreach ($logs as $log) {
    $log->event;      // AuditEvent enum (created, authenticated, revoked, etc.)
    $log->ip_address; // IP address of the request
    $log->user_agent; // User agent string
    $log->metadata;   // Additional JSON data
    $log->created_at; // Timestamp
}
```

## Configuring Audit Drivers

```php
// config/bearer.php
return [
    'audit' => [
        // Default driver
        'driver' => env('BEARER_AUDIT_DRIVER', 'database'),

        // Available drivers
        'drivers' => [
            'database' => [
                'class' => DatabaseAuditDriver::class,
                'connection' => null, // Uses default database connection
            ],
            'spatie' => [
                'class' => SpatieActivityLogDriver::class,
                'log_name' => 'bearer', // Spatie activity log name
            ],
            'null' => [
                'class' => NullAuditDriver::class, // No-op driver
            ],
        ],

        // Enable/disable usage logging (every authentication)
        'log_usage' => true,

        // How long to keep audit logs
        'retention_days' => 90,
    ],
];
```

## Using Spatie Activity Log Driver

If you're using `spatie/laravel-activitylog`:

```env
BEARER_AUDIT_DRIVER=spatie
```

Query logs via Spatie's API:

```php
use Spatie\Activitylog\Models\Activity;

$activities = Activity::inLog('bearer')
    ->forSubject($token->accessToken)
    ->latest()
    ->get();
```

## Creating a Custom Audit Driver

```php
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Database\Models\PersonalAccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Collection;

class CloudWatchAuditDriver implements AuditDriver
{
    public function __construct(
        private readonly CloudWatchClient $client,
    ) {}

    public function log(PersonalAccessToken $token, AuditEvent $event, array $context = []): void
    {
        $this->client->putLogEvents([
            'logGroupName' => 'bearer-audit',
            'logStreamName' => date('Y-m-d'),
            'logEvents' => [
                [
                    'timestamp' => now()->getTimestampMs(),
                    'message' => json_encode([
                        'token_id' => $token->id,
                        'event' => $event->value,
                        'ip_address' => request()->ip(),
                        'user_agent' => request()->userAgent(),
                        'context' => $context,
                    ]),
                ],
            ],
        ]);
    }

    public function getLogsForToken(PersonalAccessToken $token): Collection
    {
        // Query CloudWatch logs...
        return collect();
    }
}
```

Register in a service provider:

```php
use Cline\Bearer\AuditDrivers\AuditDriverRegistry;

$this->app->make(AuditDriverRegistry::class)
    ->register('cloudwatch', new CloudWatchAuditDriver($client));
```

## Pruning Old Audit Logs

Via Artisan command (schedule this daily):

```bash
php artisan bearer:prune-audit-logs --days=90
```

In `app/Console/Kernel.php`:

```php
$schedule->command('bearer:prune-audit-logs')->daily();
```

Or manually:

```php
TokenAuditLog::query()
    ->where('created_at', '<', now()->subDays(90))
    ->delete();
```

## Disabling Audit Logging

For testing or performance, use the null driver:

```env
BEARER_AUDIT_DRIVER=null
```

Or disable only usage logging (still logs create/revoke/rotate):

```php
// config/bearer.php
'audit' => [
    'log_usage' => false,
],
```

## Next Steps

- **[Usage Tracking](usage-tracking.md)** - Analyze token usage patterns
- **[Revocation & Rotation](revocation-rotation.md)** - Token lifecycle events
