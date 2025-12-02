# Rate Limiting

This guide demonstrates how to configure and use rate limiting per token type.

## Default Rate Limits (Per Token Type)

Each token type can have a default rate limit:

```php
// config/bearer.php
return [
    'types' => [
        'sk' => [
            'class' => SecretTokenType::class,
            // No rate limit for secret keys (server-to-server)
        ],
        'pk' => [
            'prefix' => 'pk',
            'name' => 'Publishable',
            'default_rate_limit' => 100, // 100 requests per minute
        ],
        'rk' => [
            'prefix' => 'rk',
            'name' => 'Restricted',
            'default_rate_limit' => 1000, // Higher for internal services
        ],
    ],
];
```

## Custom Rate Limits Per Token

Override default rate limit for specific token:

```php
use App\Models\User;
use Cline\Bearer\Facades\Bearer;

$user = User::find(1);

$token = Bearer::for($user)
    ->rateLimit(500) // 500 requests per minute
    ->issue('pk', 'High-traffic Widget');
```

No rate limit (null = unlimited):

```php
$unlimitedToken = Bearer::for($user)
    ->rateLimit(null)
    ->issue('sk', 'Internal Service');
```

Very restrictive rate limit:

```php
$restrictedToken = Bearer::for($user)
    ->rateLimit(10) // Only 10 requests per minute
    ->issue('pk', 'Demo Key');
```

## Rate Limit by Environment

Test environment with higher limits:

```php
$testToken = Bearer::for($user)
    ->environment('test')
    ->rateLimit(10000) // Generous limit for testing
    ->issue('pk', 'Development Key');
```

Live environment with production limits:

```php
$liveToken = Bearer::for($user)
    ->environment('live')
    ->rateLimit(100) // Standard production limit
    ->issue('pk', 'Production Key');
```

## Checking Rate Limits

```php
$token = $user->currentAccessToken();

// Get the rate limit for current token
$rateLimit = $token->rate_limit; // null = unlimited

// Check if token has rate limiting enabled
if ($token->rate_limit !== null) {
    echo "Rate limit: {$token->rate_limit} requests/minute";
}
```

## Updating Rate Limits

```php
// Increase rate limit for upgraded customer
$token->accessToken->update([
    'rate_limit' => 1000,
]);

// Remove rate limiting
$token->accessToken->update([
    'rate_limit' => null,
]);
```

## Rate Limit Middleware

Integrate with Laravel's rate limiting:

```php
// app/Providers/RouteServiceProvider.php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('bearer', function ($request) {
    $token = $request->user()?->currentAccessToken();

    if (!$token || $token->rate_limit === null) {
        return Limit::none();
    }

    return Limit::perMinute($token->rate_limit)
        ->by($token->id);
});
```

In routes:

```php
// routes/api.php
Route::middleware(['auth:bearer', 'throttle:bearer'])->group(function () {
    Route::get('/data', [DataController::class, 'index']);
});
```

## Handling Rate Limit Exceeded

```php
use Cline\Bearer\Exceptions\RateLimitException;

// app/Exceptions/Handler.php
$this->renderable(function (RateLimitException $e) {
    return response()->json([
        'error' => 'rate_limit_exceeded',
        'message' => 'Too many requests. Please slow down.',
        'retry_after' => $e->retryAfter,
    ], 429)->withHeaders([
        'Retry-After' => $e->retryAfter,
        'X-RateLimit-Limit' => $e->limit,
        'X-RateLimit-Remaining' => 0,
    ]);
});
```

## Custom Rate Limit Keys

Rate limit by token + endpoint combination:

```php
RateLimiter::for('bearer-endpoint', function ($request) {
    $token = $request->user()?->currentAccessToken();

    if (!$token) {
        return Limit::perMinute(60)->by($request->ip());
    }

    $baseLimit = $token->rate_limit ?? 1000;
    $endpoint = $request->route()->getName();

    // Different limits per endpoint
    $multipliers = [
        'api.search' => 0.1,  // 10% of base (expensive operation)
        'api.export' => 0.05, // 5% of base (very expensive)
        'api.read' => 1.0,    // Full limit
    ];

    $multiplier = $multipliers[$endpoint] ?? 1.0;

    return Limit::perMinute((int) ($baseLimit * $multiplier))
        ->by($token->id . '|' . $endpoint);
});
```

## Next Steps

- **[Usage Tracking](usage-tracking.md)** - Monitor token activity
- **[Audit Logging](audit-logging.md)** - Record rate limit events
