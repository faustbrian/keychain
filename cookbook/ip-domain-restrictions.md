# IP & Domain Restrictions

This guide demonstrates how to restrict tokens by IP address and domain.

## IP Restrictions

Restrict token to specific IP addresses:

```php
use App\Models\User;
use Cline\Bearer\Facades\Bearer;

$token = Bearer::for($user)
    ->allowedIps(['192.168.1.100', '10.0.0.50'])
    ->issue('sk', 'Office Server Key');
```

Restrict to IP ranges (CIDR notation):

```php
$token = Bearer::for($user)
    ->allowedIps([
        '192.168.1.0/24',    // All IPs in 192.168.1.x
        '10.0.0.0/8',        // All IPs in 10.x.x.x
        '172.16.0.0/12',     // Private network range
    ])
    ->issue('sk', 'Internal Network Key');
```

Mix specific IPs and ranges:

```php
$token = Bearer::for($user)
    ->allowedIps([
        '203.0.113.50',      // Specific production server
        '198.51.100.0/24',   // Staging network
        '2001:db8::/32',     // IPv6 range
    ])
    ->issue('sk', 'Production Key');
```

## Domain Restrictions

Domain restrictions are primarily for Publishable Keys used in client-side applications.

Restrict to specific domains:

```php
$token = Bearer::for($user)
    ->allowedDomains(['example.com', 'www.example.com'])
    ->issue('pk', 'Website Widget Key');
```

Wildcard subdomains:

```php
$token = Bearer::for($user)
    ->allowedDomains([
        '*.example.com',     // All subdomains of example.com
        'example.com',       // Root domain
    ])
    ->issue('pk', 'Multi-site Key');
```

Multiple domains (for SaaS white-label scenarios):

```php
$token = Bearer::for($user)
    ->allowedDomains([
        '*.myapp.com',
        '*.customer1.com',
        '*.customer2.com',
        'localhost',         // For development
        'localhost:3000',    // With port
    ])
    ->issue('pk', 'White-label Key');
```

## Combining IP and Domain Restrictions

Both must pass for the token to be valid:

```php
$token = Bearer::for($user)
    ->allowedIps(['192.168.1.0/24'])
    ->allowedDomains(['*.internal.example.com'])
    ->issue('pk', 'Internal Dashboard Key');
```

## Stripe-Style Patterns

Secret keys: IP restricted, no domain restriction:

```php
$secretKey = Bearer::for($user)
    ->allowedIps(['production-server-ip'])
    ->environment('live')
    ->issue('sk', 'Production Server');
```

Publishable keys: Domain restricted, no IP restriction:

```php
$publishableKey = Bearer::for($user)
    ->allowedDomains(['checkout.example.com', '*.example.com'])
    ->environment('live')
    ->issue('pk', 'Checkout Widget');
```

Restricted keys: Both restrictions for microservices:

```php
$restrictedKey = Bearer::for($user)
    ->allowedIps(['10.0.0.0/8']) // Internal network only
    ->environment('live')
    ->issue('rk', 'Payment Microservice');
```

## Updating Restrictions

Add IPs to existing token:

```php
$token->accessToken->update([
    'allowed_ips' => array_merge(
        $token->accessToken->allowed_ips ?? [],
        ['new-ip-address']
    ),
]);
```

Replace all allowed domains:

```php
$token->accessToken->update([
    'allowed_domains' => ['new-domain.com', '*.new-domain.com'],
]);
```

Remove all restrictions:

```php
$token->accessToken->update([
    'allowed_ips' => null,
    'allowed_domains' => null,
]);
```

## Checking Restrictions Programmatically

```php
$token = $user->currentAccessToken();

// Check if token has IP restrictions
if ($token->allowed_ips !== null) {
    $allowedIps = $token->allowed_ips;
}

// Check if token has domain restrictions
if ($token->allowed_domains !== null) {
    $allowedDomains = $token->allowed_domains;
}
```

## Handling Restriction Errors

```php
use Cline\Bearer\Exceptions\IpRestrictionException;
use Cline\Bearer\Exceptions\DomainRestrictionException;

// In app/Exceptions/Handler.php:
$this->renderable(function (IpRestrictionException $e) {
    return response()->json([
        'error' => 'ip_restricted',
        'message' => 'This API key is not allowed from your IP address.',
    ], 403);
});

$this->renderable(function (DomainRestrictionException $e) {
    return response()->json([
        'error' => 'domain_restricted',
        'message' => 'This API key is not allowed from this domain.',
    ], 403);
});
```

## Development & Testing

For development, include localhost:

```php
$token = Bearer::for($user)
    ->allowedDomains([
        'localhost',
        'localhost:3000',
        '127.0.0.1',
        '*.example.com',
    ])
    ->issue('pk', 'Development Key');
```

For testing, you might want no restrictions:

```php
$token = Bearer::for($user)
    ->environment('test')
    ->issue('pk', 'Test Key');
// Test environment tokens often have relaxed or no restrictions by default
```

## Next Steps

- **[Rate Limiting](rate-limiting.md)** - Throttling token usage
- **[Authentication](authentication.md)** - Middleware for checking restrictions
