# Token Metadata

This guide demonstrates how to store and use custom metadata with tokens.

## Storing Metadata

Add metadata during token creation:

```php
use App\Models\User;
use Cline\Bearer\Facades\Bearer;

$user = User::find(1);

$token = Bearer::for($user)
    ->metadata([
        'purpose' => 'payment_processing',
        'created_by' => 'admin@example.com',
        'department' => 'engineering',
    ])
    ->issue('sk', 'Payment Service Key');
```

Complex metadata structures:

```php
$token = Bearer::for($user)
    ->metadata([
        'integration' => [
            'type' => 'webhook',
            'version' => '2.0',
            'events' => ['payment.completed', 'payment.failed'],
        ],
        'limits' => [
            'max_amount' => 10000,
            'currency' => 'USD',
        ],
        'contact' => [
            'email' => 'dev@example.com',
            'slack' => '#payments-alerts',
        ],
    ])
    ->issue('sk', 'Webhook Integration');
```

## Reading Metadata

```php
$token = $user->currentAccessToken();

// Get all metadata
$metadata = $token->metadata; // Returns array or null

// Check if metadata exists
if ($token->metadata !== null) {
    $purpose = $token->metadata['purpose'] ?? 'general';
}

// Safe access with null coalescing
$department = $token->metadata['department'] ?? 'unknown';
$maxAmount = $token->metadata['limits']['max_amount'] ?? 0;
```

## Updating Metadata

Replace all metadata:

```php
$token->accessToken->update([
    'metadata' => [
        'purpose' => 'updated_purpose',
        'version' => '2.0',
    ],
]);
```

Merge with existing metadata:

```php
$token->accessToken->update([
    'metadata' => array_merge(
        $token->accessToken->metadata ?? [],
        ['last_reviewed' => now()->toISOString()]
    ),
]);
```

Add a single key:

```php
$currentMetadata = $token->accessToken->metadata ?? [];
$currentMetadata['audit_note'] = 'Reviewed by security team';
$token->accessToken->update(['metadata' => $currentMetadata]);
```

Remove a key:

```php
$currentMetadata = $token->accessToken->metadata ?? [];
unset($currentMetadata['temporary_flag']);
$token->accessToken->update(['metadata' => $currentMetadata]);
```

Clear all metadata:

```php
$token->accessToken->update(['metadata' => null]);
```

## Querying by Metadata

```php
use Cline\Bearer\Database\Models\PersonalAccessToken;

// Find tokens by metadata value (JSON queries)
$paymentTokens = PersonalAccessToken::query()
    ->whereJsonContains('metadata->purpose', 'payment_processing')
    ->get();

// Find tokens by nested metadata
$webhookTokens = PersonalAccessToken::query()
    ->where('metadata->integration->type', 'webhook')
    ->get();

// Find tokens with specific event subscriptions
$paymentEventTokens = PersonalAccessToken::query()
    ->whereJsonContains('metadata->integration->events', 'payment.completed')
    ->get();

// Find tokens by department
$engineeringTokens = PersonalAccessToken::query()
    ->where('metadata->department', 'engineering')
    ->where('revoked_at', null)
    ->get();
```

## Use Cases

### Track Token Creator/Approver

```php
$token = Bearer::for($user)
    ->metadata([
        'created_by' => auth()->id(),
        'approved_by' => $approver->id,
        'approval_date' => now()->toISOString(),
        'ticket' => 'JIRA-1234',
    ])
    ->issue('sk', 'Production API Key');
```

### Customer/Tenant Identification

```php
$token = Bearer::for($user)
    ->metadata([
        'customer_id' => $customer->id,
        'plan' => 'enterprise',
        'features' => ['advanced_analytics', 'custom_reports'],
    ])
    ->issue('sk', "Customer {$customer->name}");
```

### Integration-Specific Configuration

```php
$token = Bearer::for($user)
    ->metadata([
        'webhook_url' => 'https://example.com/webhooks',
        'webhook_secret' => 'whsec_...',
        'retry_policy' => ['max_attempts' => 3, 'backoff' => 'exponential'],
    ])
    ->issue('sk', 'Webhook Delivery');
```

### Compliance and Audit Tracking

```php
$token = Bearer::for($user)
    ->metadata([
        'compliance' => [
            'pci_scope' => true,
            'data_classification' => 'confidential',
            'review_required_by' => now()->addMonths(3)->toISOString(),
        ],
        'security_review' => [
            'reviewer' => 'security@example.com',
            'date' => now()->toISOString(),
            'findings' => 'none',
        ],
    ])
    ->issue('sk', 'PCI Compliant Key');
```

### Feature Flags per Token

```php
$token = Bearer::for($user)
    ->metadata([
        'features' => [
            'beta_api_v2' => true,
            'experimental_search' => false,
            'legacy_support' => true,
        ],
    ])
    ->issue('sk', 'Beta Tester Key');

// Then in your API:
$features = $request->user()->currentAccessToken()->metadata['features'] ?? [];
if ($features['beta_api_v2'] ?? false) {
    // Use v2 API logic
}
```

## Metadata Validation

You can validate metadata in a custom token type:

```php
use Cline\Bearer\TokenTypes\AbstractTokenType;

final class ValidatedTokenType extends AbstractTokenType
{
    public function validateMetadata(array $metadata): void
    {
        $required = ['purpose', 'department'];

        foreach ($required as $key) {
            if (!isset($metadata[$key])) {
                throw new InvalidArgumentException("Metadata must include '{$key}'");
            }
        }

        $allowedPurposes = ['development', 'production', 'testing'];
        if (!in_array($metadata['purpose'], $allowedPurposes, true)) {
            throw new InvalidArgumentException('Invalid purpose');
        }
    }
}
```

## Next Steps

- **[Revocation & Rotation](revocation-rotation.md)** - Token lifecycle management
- **[Audit Logging](audit-logging.md)** - Recording token events
