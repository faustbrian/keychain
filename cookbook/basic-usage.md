# Basic Usage

This guide demonstrates the fundamental operations of the Bearer package.

## Issuing Tokens

Issue a single secret key (server-side only):

```php
use App\Models\User;
use Cline\Bearer\Facades\Bearer;

$user = User::find(1);
$token = Bearer::for($user)->issue(
    type: 'sk',
    name: 'Production API Key',
);

// The plain text token is only available at creation time
echo $token->plainTextToken; // sk_test_abc123...

// Access the token model
$token->accessToken->type;        // 'sk'
$token->accessToken->environment; // 'test'
$token->accessToken->name;        // 'Production API Key'
```

## Issuing Token Groups

Issue a group of related tokens (sk, pk, rk linked together):

```php
$group = Bearer::for($user)->issueGroup(
    types: ['sk', 'pk', 'rk'],
    name: 'Payment Integration Keys',
);

// Access individual tokens in the group
$secretKey = $group->secretKey();           // sk_test_...
$publishableKey = $group->publishableKey(); // pk_test_...
$restrictedKey = $group->restrictedKey();   // rk_test_...

// Find sibling tokens
$pkFromSk = $secretKey->sibling('pk'); // Get publishable key from secret key's group
```

## Configuring Tokens

Issue with custom configuration using the fluent API:

```php
$token = Bearer::for($user)
    ->environment('live')                          // Set environment
    ->abilities(['users:read', 'orders:write'])    // Custom abilities
    ->allowedIps(['192.168.1.0/24', '10.0.0.1'])   // IP restrictions
    ->allowedDomains(['*.example.com'])            // Domain restrictions
    ->rateLimit(100)                               // 100 requests per minute
    ->expiresIn(60 * 24 * 30)                      // Expires in 30 days
    ->issue('pk', 'Frontend Widget Key');
```

## Finding Tokens

```php
// Find by plain text token
$token = Bearer::findToken('sk_test_abc123...');

// Find by prefix (partial match)
$token = Bearer::findByPrefix('sk_test_abc');
```

## Using the HasApiTokens Trait

Add the trait to your User model:

```php
use Cline\Bearer\Concerns\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens;
}
```

Then use the convenience methods:

```php
// Create token via user model
$token = $user->createToken('sk', 'My Token');

// Create token group via user model
$group = $user->createTokenGroup(['sk', 'pk'], 'My Keys');

// Check current token abilities
if ($user->tokenCan('users:write')) {
    // User has write access
}

// Check token type
if ($user->tokenIs('sk')) {
    // Using a secret key
}

// Get current token environment
$env = $user->tokenEnvironment(); // 'test' or 'live'
```

## Next Steps

- **[Authentication](authentication.md)** - Protecting routes and checking permissions
- **[Custom Token Types](custom-token-types.md)** - Creating your own token types
- **[Token Metadata](token-metadata.md)** - Attaching custom data to tokens
