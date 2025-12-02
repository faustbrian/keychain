# Authentication

This guide demonstrates how to authenticate requests using Bearer tokens.

## Protecting Routes

Basic authentication with any valid token:

```php
// routes/api.php
use Illuminate\Support\Facades\Route;

Route::middleware('auth:bearer')->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
```

## Checking Abilities

Require **all** specified abilities:

```php
Route::middleware(['auth:bearer', 'abilities:users:read,users:write'])->group(function () {
    Route::get('/users', [UserController::class, 'index']);
    Route::post('/users', [UserController::class, 'store']);
});
```

Require **any** of the specified abilities:

```php
Route::middleware(['auth:bearer', 'ability:admin,moderator'])->group(function () {
    Route::get('/admin/dashboard', [AdminController::class, 'dashboard']);
});
```

## Checking Token Type

Only allow secret keys (server-side endpoints):

```php
Route::middleware(['auth:bearer', 'token-type:sk'])->group(function () {
    Route::post('/webhooks', [WebhookController::class, 'handle']);
    Route::post('/payments', [PaymentController::class, 'charge']);
});
```

Only allow publishable keys (client-side endpoints):

```php
Route::middleware(['auth:bearer', 'token-type:pk'])->group(function () {
    Route::post('/checkout/session', [CheckoutController::class, 'createSession']);
});
```

Allow multiple token types:

```php
Route::middleware(['auth:bearer', 'token-type:sk,rk'])->group(function () {
    Route::get('/internal/status', [StatusController::class, 'index']);
});
```

## Checking Environment

Only allow live environment tokens:

```php
Route::middleware(['auth:bearer', 'environment:live'])->group(function () {
    Route::post('/payments/charge', [PaymentController::class, 'charge']);
});
```

Only allow test environment tokens:

```php
Route::middleware(['auth:bearer', 'environment:test'])->group(function () {
    Route::post('/test/webhook', [TestController::class, 'simulateWebhook']);
});
```

## Combining Middleware

Require: valid token + secret key + live environment + payment ability:

```php
Route::middleware([
    'auth:bearer',
    'token-type:sk',
    'environment:live',
    'abilities:payments:charge',
])->group(function () {
    Route::post('/payments/charge', [PaymentController::class, 'charge']);
});
```

## In Controllers

```php
use Illuminate\Http\Request;

class ApiController extends Controller
{
    public function index(Request $request)
    {
        $user = $request->user();
        $token = $user->currentAccessToken();

        // Check token type
        if ($user->tokenIs('pk')) {
            return $this->limitedResponse();
        }

        // Check abilities
        if ($user->tokenCan('admin')) {
            return $this->adminResponse();
        }

        // Check environment
        if ($user->tokenEnvironment() === 'test') {
            return $this->testResponse();
        }

        return $this->standardResponse();
    }
}
```

## Testing with actingAs

```php
use Cline\Bearer\Bearer;
use Tests\TestCase;

class ApiTest extends TestCase
{
    public function test_user_can_access_api(): void
    {
        $user = User::factory()->create();

        // Act as user with specific abilities
        Bearer::actingAs($user, ['users:read', 'users:write']);

        $response = $this->getJson('/api/users');

        $response->assertOk();
    }

    public function test_secret_key_required(): void
    {
        $user = User::factory()->create();

        // Act as user with specific token type
        Bearer::actingAs($user, ['*'], 'sk');

        $response = $this->postJson('/api/webhooks');

        $response->assertOk();
    }
}
```

## Stateful Authentication (SPA/First-Party)

Configure stateful domains for session-based auth:

```php
// config/bearer.php
'stateful' => ['localhost', 'spa.example.com', '*.example.com']
```

These domains will use session-based auth (cookies) instead of tokens. Perfect for first-party SPAs where you don't want to expose tokens.

```php
// routes/api.php
Route::middleware('auth:bearer')->group(function () {
    // Works with both:
    // 1. Bearer tokens (Authorization: Bearer sk_test_...)
    // 2. Session cookies (for stateful domains)
    Route::get('/user', fn (Request $request) => $request->user());
});
```

## Next Steps

- **[IP & Domain Restrictions](ip-domain-restrictions.md)** - Network-based access control
- **[Rate Limiting](rate-limiting.md)** - Throttling token usage
- **[Audit Logging](audit-logging.md)** - Recording token events
