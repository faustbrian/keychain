# Custom Token Types

This guide demonstrates how to create and register custom token types.

## Using Configurable Token Types (Via Config)

Add custom types directly in your configuration:

```php
// config/bearer.php
return [
    'types' => [
        // Built-in types
        'sk' => ['class' => SecretTokenType::class],
        'pk' => ['class' => PublishableTokenType::class],
        'rk' => ['class' => RestrictedTokenType::class],

        // Custom type via config
        'wh' => [
            'prefix' => 'wh',
            'name' => 'Webhook',
            'server_side_only' => true,
            'default_abilities' => ['webhooks:receive'],
            'default_expiration' => null, // Never expires
            'default_rate_limit' => 10000, // High limit for webhooks
            'allowed_environments' => ['test', 'live'],
        ],

        // Another custom type
        'tmp' => [
            'prefix' => 'tmp',
            'name' => 'Temporary',
            'server_side_only' => false,
            'default_abilities' => ['read'],
            'default_expiration' => 60, // 1 hour
            'default_rate_limit' => 100,
            'allowed_environments' => ['test'],
        ],
    ],
];
```

Now use them:

```php
$webhookToken = Bearer::for($user)->issue('wh', 'Stripe Webhooks');
$tempToken = Bearer::for($user)->issue('tmp', 'One-time Access');
```

## Creating a Custom Token Type Class

```php
use Cline\Bearer\TokenTypes\AbstractTokenType;

final class WebhookTokenType extends AbstractTokenType
{
    public function __construct()
    {
        parent::__construct(
            name: 'Webhook',
            prefix: 'wh',
            defaultAbilities: ['webhooks:receive', 'webhooks:verify'],
            defaultExpiration: null, // Never expires
            defaultRateLimit: 50000, // Very high limit
            allowedEnvironments: ['test', 'live'],
            serverSideOnly: true,
        );
    }
}
```

Register in config:

```php
// config/bearer.php
'types' => [
    'wh' => ['class' => App\Bearer\WebhookTokenType::class],
],
```

## Creating a Scoped Token Type

For multi-tenant applications where each tenant has their own token type:

```php
final class TenantTokenType extends AbstractTokenType
{
    public function __construct(
        private readonly string $tenantId,
    ) {
        parent::__construct(
            name: "Tenant {$tenantId}",
            prefix: "t{$tenantId}",
            defaultAbilities: ['tenant:access'],
            defaultExpiration: 60 * 24 * 365, // 1 year
            defaultRateLimit: 1000,
            allowedEnvironments: ['live'],
            serverSideOnly: false,
        );
    }
}
```

Register dynamically in a service provider:

```php
use Cline\Bearer\TokenTypes\TokenTypeRegistry;

$this->app->afterResolving(TokenTypeRegistry::class, function (TokenTypeRegistry $registry) {
    foreach (Tenant::all() as $tenant) {
        $registry->register(
            "t{$tenant->id}",
            new TenantTokenType($tenant->id)
        );
    }
});
```

## Implementing the TokenType Interface Directly

```php
use Cline\Bearer\Contracts\TokenType;

final class ApiKeyTokenType implements TokenType
{
    public function name(): string
    {
        return 'API Key';
    }

    public function prefix(): string
    {
        return 'api';
    }

    public function defaultAbilities(): array
    {
        return config('api.default_abilities', ['api:read']);
    }

    public function defaultExpiration(): ?int
    {
        return null; // Never expires
    }

    public function defaultRateLimit(): ?int
    {
        return config('api.rate_limit', 1000);
    }

    public function allowedEnvironments(): array
    {
        return ['test', 'live', 'staging'];
    }

    public function isServerSideOnly(): bool
    {
        return true;
    }
}
```

## Token Types with Custom Generators

Specify a different generator per token type:

```php
// config/bearer.php
'types' => [
    'sk' => [
        'class' => SecretTokenType::class,
        'generator' => 'seam', // Stripe-style: sk_test_abc123
    ],
    'pk' => [
        'class' => PublishableTokenType::class,
        'generator' => 'uuid', // UUID-style: pk_test_550e8400-e29b-...
    ],
    'legacy' => [
        'prefix' => 'leg',
        'name' => 'Legacy',
        'generator' => 'random', // Sanctum-style random string
    ],
],
```

## Validating Token Types

```php
use Cline\Bearer\TokenTypes\TokenTypeRegistry;

$registry = app(TokenTypeRegistry::class);

// Check if type exists
if ($registry->has('custom')) {
    $type = $registry->get('custom');
}

// Find type by prefix (useful when parsing incoming tokens)
$type = $registry->findByPrefix('wh'); // Returns WebhookTokenType

// Get all registered types
$allTypes = $registry->all(); // ['sk' => ..., 'pk' => ..., 'wh' => ...]
```

## Next Steps

- **[Token Generators](token-generators.md)** - Custom token generation strategies
- **[Token Metadata](token-metadata.md)** - Attaching custom data to tokens
