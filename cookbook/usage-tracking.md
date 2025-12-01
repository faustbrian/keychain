# Usage Tracking

This guide demonstrates how to track and query token usage history.

## Automatic Usage Tracking

Bearer automatically tracks every authentication event. Unlike Sanctum's simple `last_used_at`, we maintain full history.

Each authentication creates an audit log entry with:
- Event type (Authenticated)
- IP address
- User agent
- Timestamp
- Custom metadata

## Querying Usage History

```php
use Cline\Bearer\Enums\AuditEvent;

$token = $user->currentAccessToken();

// Get all usage (authentications) for a token
$usage = $token->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->get();

// Get usage count
$totalUses = $token->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->count();

// Get recent usage
$recentUsage = $token->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->where('created_at', '>', now()->subDays(7))
    ->latest()
    ->get();

// Get first and last usage
$firstUse = $token->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->oldest()
    ->first();

$lastUse = $token->auditLogs()
    ->where('event', AuditEvent::Authenticated->value)
    ->latest()
    ->first();
```

## Usage Patterns & Analytics

Daily usage counts:

```php
use Cline\Bearer\Database\Models\TokenAuditLog;

$dailyUsage = TokenAuditLog::query()
    ->where('personal_access_token_id', $token->id)
    ->where('event', AuditEvent::Authenticated->value)
    ->where('created_at', '>', now()->subDays(30))
    ->selectRaw('DATE(created_at) as date, COUNT(*) as count')
    ->groupBy('date')
    ->orderBy('date')
    ->get();
```

Hourly distribution:

```php
$hourlyUsage = TokenAuditLog::query()
    ->where('personal_access_token_id', $token->id)
    ->where('event', AuditEvent::Authenticated->value)
    ->selectRaw('HOUR(created_at) as hour, COUNT(*) as count')
    ->groupBy('hour')
    ->orderBy('hour')
    ->get();
```

Usage by IP address:

```php
$usageByIp = TokenAuditLog::query()
    ->where('personal_access_token_id', $token->id)
    ->where('event', AuditEvent::Authenticated->value)
    ->selectRaw('ip_address, COUNT(*) as count')
    ->groupBy('ip_address')
    ->orderByDesc('count')
    ->get();
```

## User-Level Usage Analytics

```php
use Cline\Bearer\Database\Models\PersonalAccessToken;

$user = User::find(1);

// Total usage across all user's tokens
$totalUserUsage = TokenAuditLog::query()
    ->whereHas('token', function ($query) use ($user) {
        $query->where('tokenable_type', get_class($user))
              ->where('tokenable_id', $user->id);
    })
    ->where('event', AuditEvent::Authenticated->value)
    ->count();

// Most active tokens
$mostActiveTokens = PersonalAccessToken::query()
    ->where('tokenable_type', get_class($user))
    ->where('tokenable_id', $user->id)
    ->withCount(['auditLogs' => function ($query) {
        $query->where('event', AuditEvent::Authenticated->value);
    }])
    ->orderByDesc('audit_logs_count')
    ->limit(10)
    ->get();
```

## Tracking Failures & Security Events

Failed authentication attempts:

```php
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

Suspicious activity (many failures from same IP):

```php
$suspiciousIps = TokenAuditLog::query()
    ->whereIn('event', [
        AuditEvent::Failed->value,
        AuditEvent::IpBlocked->value,
    ])
    ->where('created_at', '>', now()->subHours(1))
    ->selectRaw('ip_address, COUNT(*) as count')
    ->groupBy('ip_address')
    ->having('count', '>', 10)
    ->get();
```

## Lifecycle Event Tracking

```php
$lifecycleEvents = TokenAuditLog::query()
    ->where('personal_access_token_id', $token->id)
    ->whereIn('event', [
        AuditEvent::Created->value,
        AuditEvent::Rotated->value,
        AuditEvent::Revoked->value,
    ])
    ->orderBy('created_at')
    ->get();
```

## Usage Statistics Dashboard

Build a usage statistics summary:

```php
function getUsageStatistics(User $user, int $days = 30): array
{
    $startDate = now()->subDays($days);

    $tokens = PersonalAccessToken::query()
        ->where('tokenable_type', get_class($user))
        ->where('tokenable_id', $user->id)
        ->get();

    $tokenIds = $tokens->pluck('id');

    $auditLogs = TokenAuditLog::query()
        ->whereIn('personal_access_token_id', $tokenIds)
        ->where('created_at', '>', $startDate);

    return [
        'total_tokens' => $tokens->count(),
        'active_tokens' => $tokens->whereNull('revoked_at')->count(),
        'total_requests' => (clone $auditLogs)
            ->where('event', AuditEvent::Authenticated->value)
            ->count(),
        'unique_ips' => (clone $auditLogs)
            ->where('event', AuditEvent::Authenticated->value)
            ->distinct('ip_address')
            ->count('ip_address'),
        'failed_attempts' => (clone $auditLogs)
            ->whereIn('event', [
                AuditEvent::Failed->value,
                AuditEvent::Expired->value,
                AuditEvent::IpBlocked->value,
            ])
            ->count(),
        'by_environment' => [
            'test' => $tokens->where('environment', 'test')->count(),
            'live' => $tokens->where('environment', 'live')->count(),
        ],
        'by_type' => [
            'sk' => $tokens->where('type', 'sk')->count(),
            'pk' => $tokens->where('type', 'pk')->count(),
            'rk' => $tokens->where('type', 'rk')->count(),
        ],
    ];
}
```

## Performance: Disabling Usage Logging

For high-traffic applications, you may want to disable per-request logging:

```php
// config/bearer.php
'audit' => [
    'log_usage' => false, // Disable per-authentication logging
],
```

This still logs lifecycle events (create, revoke, rotate) but not each authentication request. You can then rely on:
- The `last_used_at` column (updated on each auth)
- External logging systems (CloudWatch, DataDog, etc.)
- Custom middleware for selective logging

## Custom Usage Tracking

Add custom metadata to authentication logs:

```php
use Cline\Bearer\Events\TokenAuthenticated;

Event::listen(TokenAuthenticated::class, function (TokenAuthenticated $event) {
    $event->token->auditLogs()->latest()->first()?->update([
        'metadata' => array_merge(
            $event->token->auditLogs()->latest()->first()?->metadata ?? [],
            [
                'endpoint' => request()->path(),
                'method' => request()->method(),
                'response_time_ms' => defined('LARAVEL_START')
                    ? round((microtime(true) - LARAVEL_START) * 1000)
                    : null,
            ]
        ),
    ]);
});
```

## Next Steps

- **[Audit Logging](audit-logging.md)** - Configure audit drivers
- **[Rate Limiting](rate-limiting.md)** - Throttle based on usage patterns
