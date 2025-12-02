# Revocation & Rotation

This guide demonstrates how to revoke and rotate tokens.

## Revoking Tokens

```php
use App\Models\User;
use Cline\Bearer\Facades\Bearer;

$user = User::find(1);
$token = Bearer::for($user)->issue('sk', 'API Key');

// Simple revocation (only this token)
Bearer::revoke($token->accessToken);

// Check if revoked
$token->accessToken->isRevoked(); // true
```

## Revocation Modes

```php
use Cline\Bearer\Enums\RevocationMode;

// Create a token group first
$group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Payment Keys');
$secretKey = $group->secretKey();
```

### None

Only revoke the specified token:

```php
Bearer::revoke($secretKey, RevocationMode::None);
// Result: Only sk is revoked, pk and rk remain valid
```

### Cascade

Revoke all tokens in the group:

```php
$group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');
Bearer::revoke($group->secretKey(), RevocationMode::Cascade);
// Result: sk, pk, and rk are ALL revoked
```

### Partial

Revoke only server-side tokens (sk, rk) but keep pk valid:

```php
$group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');
Bearer::revoke($group->secretKey(), RevocationMode::Partial);
// Result: sk and rk are revoked, pk remains valid
```

### Timed

Schedule revocation for later (default 60 minutes):

```php
$group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');
Bearer::revoke($group->secretKey(), RevocationMode::Timed);
// Result: Token will be invalid after 60 minutes
```

## Rotating Tokens

```php
$token = Bearer::for($user)->issue('sk', 'API Key');

// Simple rotation (immediate invalidation of old token)
$newToken = Bearer::rotate($token->accessToken);

// The new token has the same configuration
echo $newToken->plainTextToken; // sk_test_newtoken...

// Old token is now invalid
$token->accessToken->fresh()->isRevoked(); // true
```

## Rotation Modes

```php
use Cline\Bearer\Enums\RotationMode;
```

### Immediate

Old token invalid immediately (default):

```php
$newToken = Bearer::rotate($token->accessToken, RotationMode::Immediate);
// Result: Old token is revoked immediately
```

### Grace Period

Old token valid for a grace period (default 60 minutes):

```php
$newToken = Bearer::rotate($token->accessToken, RotationMode::GracePeriod);
// Result: Both tokens work for 60 minutes, then old token becomes invalid
```

### Dual Valid

Both tokens remain valid until explicit revocation:

```php
$newToken = Bearer::rotate($token->accessToken, RotationMode::DualValid);
// Result: Both tokens work indefinitely until you manually revoke the old one
```

## Fluent Revocation API

```php
use Cline\Bearer\Conductors\TokenRevocationConductor;

$conductor = new TokenRevocationConductor(app(BearerManager::class), $token->accessToken);
$conductor
    ->using(RevocationMode::Cascade)
    ->withReason('Security incident - compromised credentials')
    ->revoke();
```

## Fluent Rotation API

```php
use Cline\Bearer\Conductors\TokenRotationConductor;

$conductor = new TokenRotationConductor(app(BearerManager::class), $token->accessToken);
$newToken = $conductor
    ->using(RotationMode::GracePeriod)
    ->withGracePeriod(120) // 2 hours
    ->rotate();
```

## Batch Operations

```php
// Revoke all tokens for a user
$user->tokens()->update(['revoked_at' => now()]);

// Revoke all tokens of a specific type
$user->tokens()->where('type', 'pk')->update(['revoked_at' => now()]);

// Revoke all test environment tokens
$user->tokens()->where('environment', 'test')->update(['revoked_at' => now()]);

// Revoke entire group
$group->revokeAll();
```

## Next Steps

- **[Audit Logging](audit-logging.md)** - Track all revocation and rotation events
- **[Usage Tracking](usage-tracking.md)** - Monitor token activity before revoking
