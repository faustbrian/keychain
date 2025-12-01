# Derived Keys

This guide covers token derivation, which enables hierarchical token structures where parent tokens can create child tokens with inherited restrictions but more limited abilities and lifespans.

## Overview

Token derivation is useful for reseller scenarios where master tokens need to issue customer tokens without those customers requiring full accounts in your system. Child tokens:

- **Inherit restrictions** from their parent (IP/domain/rate limits)
- **Have limited abilities** (subset of parent abilities)
- **Cannot outlive their parent** (expiration ≤ parent expiration)
- **Are automatically revoked** when parent is revoked (with cascade_descendants strategy)

## Prerequisites

Token derivation requires the `cline/ancestry` package for hierarchical management:

```bash
composer require cline/ancestry
php artisan vendor:publish --tag=ancestry-migrations
php artisan migrate
```

## Configuration

Configure derivation in `config/bearer.php`:

```php
'derivation' => [
    'enabled' => true,
    'max_depth' => 3, // master -> reseller -> customer
    'hierarchy_type' => 'token_derivation',
    'inherit_restrictions' => true,
    'enforce_ability_subset' => true,
    'enforce_expiration' => true,
],
```

## Basic Usage

### Create a Master Token

```php
use Cline\Bearer\Facades\Bearer;

$reseller = User::find(1);

$masterToken = Bearer::for($reseller)
    ->abilities(['invoices:read', 'invoices:write', 'webhooks:receive'])
    ->allowedIps(['192.168.1.0/24'])
    ->expiresAt(now()->addYear())
    ->issue('sk', 'Reseller Master Key');
```

### Derive a Child Token

```php
$customerToken = Bearer::derive($masterToken->accessToken)
    ->abilities(['invoices:read', 'webhooks:receive']) // Subset of parent
    ->metadata([
        'reseller_customer_id' => 'cust_xyz',
        'billing_account' => 'acc_789',
    ])
    ->expiresAt(now()->addMonths(6)) // Must be <= parent expiration
    ->as('Customer XYZ Key');

// Use the plain-text token once
echo $customerToken->plainTextToken;
// sk_live_abc123...
```

## Derived Metadata

Store derivation-specific context separate from main token metadata:

```php
$customerToken = Bearer::derive($masterToken->accessToken)
    ->abilities(['orders:read'])
    ->metadata([
        'reseller_id' => 'res_123',
        'customer_id' => 'cust_abc',
        'plan' => 'premium',
        'created_by' => 'integration_v2',
    ])
    ->as('Customer ABC');

// Access derived metadata
$metadata = $customerToken->accessToken->derived_metadata;
// ['reseller_id' => 'res_123', ...]
```

## Querying the Hierarchy

### Get Parent Token

```php
$parent = $customerToken->accessToken->parentToken();

if ($parent) {
    echo "Parent: {$parent->name}";
}
```

### Get Direct Children

```php
$children = $masterToken->accessToken->childTokens();

foreach ($children as $child) {
    echo "Child: {$child->name}\n";
}
```

### Get All Descendants

```php
$allDescendants = $masterToken->accessToken->allDescendantTokens();

echo "Total descendants: {$allDescendants->count()}";
```

### Check Hierarchy Position

```php
// Check if token is a root (no parent)
if ($masterToken->accessToken->isRootToken()) {
    echo "This is a master token";
}

// Check if token can derive children
if ($masterToken->accessToken->canDeriveTokens()) {
    echo "Can create child tokens";
}
```

## Multi-Level Hierarchies

Create nested derivation hierarchies up to the configured `max_depth`:

```php
// Level 0: Platform master
$platform = Bearer::for($admin)
    ->issue('sk', 'Platform Master', abilities: ['*']);

// Level 1: Reseller
$reseller = Bearer::derive($platform->accessToken)
    ->abilities(['customers:manage', 'billing:read'])
    ->as('Reseller Key');

// Level 2: Customer
$customer = Bearer::derive($reseller->accessToken)
    ->abilities(['billing:read'])
    ->as('Customer Key');

// Check depth (0-indexed)
$depth = $customer->accessToken->getAncestryDepth('token_derivation');
// 2
```

## Revocation Strategies

### Cascade Descendants

Revoke a master token and **all** derived tokens:

```php
use Cline\Bearer\Facades\Bearer;

Bearer::revoke($masterToken->accessToken)->withDescendants();

// All children and grandchildren are now revoked
```

### Check Affected Tokens

```php
use Cline\Bearer\RevocationStrategies\CascadeDescendantsStrategy;

$strategy = new CascadeDescendantsStrategy();
$affected = $strategy->getAffectedTokens($masterToken->accessToken);

echo "Revoking will affect {$affected->count()} tokens";
```

## Validation Rules

### Ability Subset

Child abilities must be a subset of parent abilities:

```php
$parent = Bearer::for($user)
    ->issue('sk', 'Parent', abilities: ['users:read', 'posts:read']);

// ✅ Valid: subset of parent
$child = Bearer::derive($parent->accessToken)
    ->abilities(['users:read'])->as('Child');

// ❌ Invalid: 'users:write' not in parent
$child = Bearer::derive($parent->accessToken)
    ->abilities(['users:read', 'users:write'])->as('Child');
// Throws InvalidDerivedAbilitiesException
```

### Expiration

Child expiration must be ≤ parent expiration:

```php
$parent = Bearer::for($user)
    ->expiresAt(now()->addDays(7))
    ->issue('sk', 'Parent', abilities: ['*']);

// ✅ Valid: expires before parent
$child = Bearer::derive($parent->accessToken)
    ->abilities(['*'])->expiresAt(now()->addDays(3))->as('Child');

// ❌ Invalid: expires after parent
$child = Bearer::derive($parent->accessToken)
    ->abilities(['*'])->expiresAt(now()->addDays(14))->as('Child');
// Throws InvalidDerivedExpirationException
```

### Parent Validity

Cannot derive from revoked or expired tokens:

```php
$parent = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);
$parent->accessToken->revoke();

// ❌ Invalid: parent is revoked
$child = Bearer::derive($parent->accessToken)
    ->abilities(['*'])->as('Child');
// Throws CannotDeriveTokenException
```

### Maximum Depth

Cannot exceed configured `max_depth`:

```php
// config: max_depth = 2

$level0 = Bearer::for($user)->issue('sk', 'Level 0', abilities: ['*']);
$level1 = Bearer::derive($level0->accessToken)->abilities(['*'])->as('Level 1');
$level2 = Bearer::derive($level1->accessToken)->abilities(['*'])->as('Level 2');

// ❌ Invalid: exceeds max depth
$level3 = Bearer::derive($level2->accessToken)->abilities(['*'])->as('Level 3');
// Throws CannotDeriveTokenException
```

## Inherited Restrictions

Child tokens automatically inherit parent restrictions:

```php
$parent = Bearer::for($user)
    ->allowedIps(['192.168.1.1', '10.0.0.0/8'])
    ->allowedDomains(['api.example.com'])
    ->rateLimit(1000)
    ->issue('sk', 'Parent', abilities: ['*']);

$child = Bearer::derive($parent->accessToken)
    ->abilities(['users:read'])->as('Child');

// Child inherits all restrictions
$child->accessToken->allowed_ips; // ['192.168.1.1', '10.0.0.0/8']
$child->accessToken->allowed_domains; // ['api.example.com']
$child->accessToken->rate_limit_per_minute; // 1000
```

## Audit Logging

Derivation events are automatically logged:

```php
use Cline\Bearer\Enums\AuditEvent;

$child = Bearer::derive($parent->accessToken)
    ->abilities(['*'])->as('Child');

// Check audit log
$auditLog = $child->accessToken->auditLogs()
    ->where('event', AuditEvent::Derived)
    ->first();

$auditLog->metadata;
// [
//     'parent_token_id' => 123,
//     'depth' => 1,
// ]
```

## Reseller Use Case Example

Complete example for a reseller platform:

```php
use Cline\Bearer\Facades\Bearer;

// 1. Reseller signs up and gets master key
$reseller = User::create([
    'name' => 'Acme Reseller',
    'email' => 'admin@acme.com',
]);

$resellerMaster = Bearer::for($reseller)
    ->abilities(['customers:manage', 'billing:read', 'webhooks:receive'])
    ->environment('live')
    ->issue('sk', 'Acme Master Key');

// 2. Reseller integrates and creates customer keys
foreach ($reseller->customers as $customer) {
    $customerKey = Bearer::derive($resellerMaster->accessToken)
        ->abilities(['billing:read', 'webhooks:receive'])
        ->metadata([
            'reseller_id' => $reseller->id,
            'customer_id' => $customer->id,
            'plan' => $customer->plan,
        ])
        ->expiresAt($customer->subscription_ends_at)
        ->as("Customer: {$customer->name}");

    // Send to customer
    $customer->notify(new ApiKeyCreated($customerKey->plainTextToken));
}

// 3. Customer makes API requests with their derived key
// The key is scoped to their data via derived_metadata

// 4. Reseller revokes all customer keys at once
Bearer::revoke($resellerMaster->accessToken)->withDescendants();
```

## Best Practices

1. **Use derived_metadata** for customer/reseller context instead of main metadata
2. **Revoke hierarchically** using `cascade_descendants` for master token invalidation
3. **Set reasonable depth limits** (3 levels usually sufficient: platform → reseller → customer)
4. **Inherit restrictions** to maintain security boundaries
5. **Log derivation events** for audit trails and billing
6. **Validate abilities** before derivation to provide clear error messages
7. **Document hierarchy structure** for your integration partners

## Related Documentation

- [Basic Usage](basic-usage.md) - Creating and managing tokens
- [Revocation & Rotation](revocation-rotation.md) - Token lifecycle management
- [Token Metadata](token-metadata.md) - Attaching and querying metadata
- [Audit Logging](audit-logging.md) - Recording token events
