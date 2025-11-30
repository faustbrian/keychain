# Token Generators

This guide demonstrates how to configure and create custom token generators.

## Built-in Generators

### Seam Generator (Default)

Stripe-style tokens with 24-character random alphanumeric string:

```
sk_test_abc123def456ghijklmn
```

### UUID Generator

UUID v4 tokens for distributed systems:

```
pk_live_550e8400-e29b-41d4-a716-446655440000
```

### Random Generator

Sanctum-style 40-character random string:

```
rk_test_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

## Configuring Generators

```php
// config/bearer.php
return [
    // Default generator for all token types
    'generator' => env('BEARER_GENERATOR', 'seam'),

    'generators' => [
        'seam' => [
            'class' => SeamTokenGenerator::class,
            'length' => 24, // Character length of random portion
        ],
        'uuid' => [
            'class' => UuidTokenGenerator::class,
        ],
        'random' => [
            'class' => RandomTokenGenerator::class,
            'length' => 40,
        ],
    ],

    // Per-type generator override
    'types' => [
        'sk' => [
            'class' => SecretTokenType::class,
            'generator' => 'seam', // Stripe-style for secret keys
        ],
        'pk' => [
            'class' => PublishableTokenType::class,
            'generator' => 'uuid', // UUIDs for publishable keys
        ],
        'rk' => [
            'class' => RestrictedTokenType::class,
            'generator' => 'random', // Sanctum-style for restricted
        ],
    ],
];
```

## Creating a Custom Generator

### Short Token Generator

```php
use Cline\Bearer\Contracts\TokenGenerator;

final class ShortTokenGenerator implements TokenGenerator
{
    public function __construct(
        private readonly int $length = 8,
    ) {}

    public function generate(string $prefix, string $environment): string
    {
        $random = substr(bin2hex(random_bytes(32)), 0, $this->length);

        return "{$prefix}_{$environment}_{$random}";
    }

    public function parse(string $token): array
    {
        $parts = explode('_', $token);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid token format');
        }

        return [
            'prefix' => $parts[0],
            'environment' => $parts[1],
            'secret' => $parts[2],
        ];
    }
}
```

### Hash Token Generator

```php
final class HashTokenGenerator implements TokenGenerator
{
    public function generate(string $prefix, string $environment): string
    {
        $timestamp = now()->getTimestampMs();
        $random = bin2hex(random_bytes(16));
        $hash = hash('sha256', $timestamp . $random);

        return "{$prefix}_{$environment}_{$hash}";
    }

    public function parse(string $token): array
    {
        $parts = explode('_', $token);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid token format');
        }

        return [
            'prefix' => $parts[0],
            'environment' => $parts[1],
            'secret' => $parts[2],
        ];
    }
}
```

### Base62 Token Generator

Shorter tokens with Base62 encoding:

```php
final class Base62TokenGenerator implements TokenGenerator
{
    private const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    public function __construct(
        private readonly int $length = 22,
    ) {}

    public function generate(string $prefix, string $environment): string
    {
        $random = $this->generateBase62($this->length);

        return "{$prefix}_{$environment}_{$random}";
    }

    public function parse(string $token): array
    {
        $parts = explode('_', $token);

        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid token format');
        }

        return [
            'prefix' => $parts[0],
            'environment' => $parts[1],
            'secret' => $parts[2],
        ];
    }

    private function generateBase62(int $length): string
    {
        $result = '';
        $alphabetLength = strlen(self::ALPHABET);

        for ($i = 0; $i < $length; $i++) {
            $result .= self::ALPHABET[random_int(0, $alphabetLength - 1)];
        }

        return $result;
    }
}
```

## Registering Custom Generators

### Via Config

```php
// config/bearer.php
'generators' => [
    'short' => [
        'class' => App\Bearer\ShortTokenGenerator::class,
        'length' => 8,
    ],
    'hash' => [
        'class' => App\Bearer\HashTokenGenerator::class,
    ],
    'base62' => [
        'class' => App\Bearer\Base62TokenGenerator::class,
        'length' => 22,
    ],
],
```

### Via Service Provider

```php
use Cline\Bearer\TokenGenerators\TokenGeneratorRegistry;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->app->afterResolving(TokenGeneratorRegistry::class, function (TokenGeneratorRegistry $registry) {
            $registry->register('short', new ShortTokenGenerator(8));
            $registry->register('hash', new HashTokenGenerator());
            $registry->register('base62', new Base62TokenGenerator(22));
        });
    }
}
```

## Token Format Examples

| Generator | Example Token |
|-----------|---------------|
| Seam | `sk_test_EXAMPLE1234567890abcd` |
| UUID | `pk_live_00000000-0000-0000-0000-000000000000` |
| Random | `rk_test_EXAMPLE1234567890abcdefghijklmnopqrst` |
| Short | `sk_test_EXAMPLE1` |
| Hash | `sk_test_[64-character-sha256-hash]` |
| Base62 | `sk_test_EXAMPLE1234567890ab` |

## Security Considerations

When creating custom generators, ensure:

1. **Use cryptographically secure random sources**: `random_bytes()`, `random_int()`
2. **Sufficient entropy**: Minimum 128 bits recommended
3. **URL-safe characters only**: Avoid `+`, `/`, `=`
4. **Consistent format**: For parsing
5. **No predictable patterns**: No sequential IDs or timestamp-only tokens

### Bad Practices

```php
// DON'T: Weak/predictable generators
mt_rand();           // Not cryptographically secure
rand();              // Not cryptographically secure
$id++;               // Sequential, predictable
time();              // Timestamp only, predictable
md5($data);          // Without random salt
```

### Good Practices

```php
// DO: Secure generators
random_bytes(32);                    // Cryptographically secure
random_int(0, $max);                 // Cryptographically secure
Str::uuid();                         // 122 bits of randomness
bin2hex(random_bytes(16));           // 128 bits of entropy
```

## Next Steps

- **[Custom Token Types](custom-token-types.md)** - Assign generators to token types
- **[Getting Started](getting-started.md)** - Configuration overview
