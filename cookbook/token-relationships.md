# Token Relationships

Bearer uses a three-tier relationship model for access tokens, enabling sophisticated multi-tenant and delegation scenarios.

## Relationship Model

| Relationship | Purpose | Required | Example |
|-------------|---------|----------|---------|
| **Owner** | Who created/owns the token | Yes | User who generated the API key |
| **Context** | What entity the token acts on behalf of | No | ServiceAccount, Application |
| **Boundary** | Tenant/workspace isolation scope | No | Team, Organization |

## Basic Usage (Owner Only)

Most tokens only need an owner - the entity that created the token:

```php
use Cline\Bearer\Facades\Bearer;

$user = User::find(1);
$token = Bearer::for($user)->issue('sk', 'My API Key');

// Access the owner relationship
$token->accessToken->owner;      // Returns the User model
$token->accessToken->owner_type; // 'App\Models\User' (or morph map alias)
$token->accessToken->owner_id;   // 1
```

## Context Relationship

The context represents what entity the token acts on behalf of. Use this when a user creates tokens for service accounts, applications, or other entities they manage.

### Setting Context

```php
$user = User::find(1);
$serviceAccount = ServiceAccount::find(5);

$token = Bearer::for($user)
    ->context($serviceAccount)
    ->issue('sk', 'Service Account Key');

// Relationships
$token->accessToken->owner;   // User#1 (who created it)
$token->accessToken->context; // ServiceAccount#5 (who it acts for)
```

### Querying by Context

Add the `HasApiTokens` trait to your context model:

```php
use Cline\Bearer\Concerns\HasApiTokens;

class ServiceAccount extends Model
{
    use HasApiTokens;
}
```

Then query tokens by context:

```php
// Get all tokens acting on behalf of this service account
$tokens = $serviceAccount->contextTokens()->get();

// Filter by type
$activeTokens = $serviceAccount->contextTokens()
    ->whereNull('revoked_at')
    ->where('type', 'sk')
    ->get();
```

## Boundary Relationship

The boundary provides tenant/workspace isolation, ensuring tokens can only operate within a specific scope. Essential for multi-tenant applications.

### Setting Boundary

```php
$user = User::find(1);
$team = Team::find(3);

$token = Bearer::for($user)
    ->boundary($team)
    ->issue('sk', 'Team API Key');

// Relationships
$token->accessToken->owner;    // User#1
$token->accessToken->boundary; // Team#3 (tenant scope)
```

### Querying by Boundary

Add the `HasApiTokens` trait to your boundary model:

```php
use Cline\Bearer\Concerns\HasApiTokens;

class Team extends Model
{
    use HasApiTokens;
}
```

Then query tokens by boundary:

```php
// Get all tokens within this team's boundary
$tokens = $team->boundaryTokens()->get();

// Count active tokens in organization
$count = $organization->boundaryTokens()
    ->whereNull('revoked_at')
    ->count();
```

## Full Three-Tier Example

Combine all three relationships for complex scenarios:

```php
$admin = User::find(1);
$serviceAccount = ServiceAccount::find(5);
$team = Team::find(3);

// Admin creates a service account token scoped to a team
$token = Bearer::for($admin)
    ->context($serviceAccount)
    ->boundary($team)
    ->abilities(['api:read', 'api:write'])
    ->environment('live')
    ->rateLimit(1000)
    ->issue('sk', 'Team Service API Key');

// Access all relationships
$token->accessToken->owner;    // User#1 (admin who created)
$token->accessToken->context;  // ServiceAccount#5 (acting on behalf of)
$token->accessToken->boundary; // Team#3 (scoped to this team)
```

## Token Groups with Relationships

Relationships are applied to all tokens in a group:

```php
$group = Bearer::for($user)
    ->context($application)
    ->boundary($organization)
    ->abilities(['*'])
    ->issueGroup(['sk', 'pk'], 'Application Keys');

// All tokens in the group inherit the same context and boundary
foreach ($group->tokens as $token) {
    $token->context;  // Same Application
    $token->boundary; // Same Organization
}
```

## Relationship Preservation

### Token Rotation

When rotating a token, context and boundary are automatically preserved:

```php
$newToken = Bearer::rotate($oldToken);

$newToken->accessToken->owner;    // Same owner
$newToken->accessToken->context;  // Same context (preserved)
$newToken->accessToken->boundary; // Same boundary (preserved)
```

### Token Derivation

When deriving a child token, context and boundary are inherited from the parent:

```php
$derivedToken = Bearer::derive($parentToken)
    ->abilities(['api:read']) // Can only restrict, not expand
    ->issue('Derived Token');

$derivedToken->accessToken->context;  // Inherited from parent
$derivedToken->accessToken->boundary; // Inherited from parent
```

## Morph Map Support

Bearer fully respects Laravel's morph map configuration. Register your morph map aliases:

```php
// In AppServiceProvider or a dedicated provider
use Illuminate\Database\Eloquent\Relations\Relation;

Relation::enforceMorphMap([
    'user' => App\Models\User::class,
    'team' => App\Models\Team::class,
    'service_account' => App\Models\ServiceAccount::class,
    'application' => App\Models\Application::class,
]);
```

With morph maps, the database stores the alias instead of the full class name:

```php
$token->owner_type;    // 'user' instead of 'App\Models\User'
$token->context_type;  // 'service_account' instead of 'App\Models\ServiceAccount'
$token->boundary_type; // 'team' instead of 'App\Models\Team'
```

## Use Cases

### SaaS Multi-Tenancy

```php
// User creates an API key for their organization
$token = Bearer::for($user)
    ->boundary($organization)
    ->issue('sk', 'Organization API Key');
```

### Service Account Delegation

```php
// Admin creates a token that acts as a service account
$token = Bearer::for($admin)
    ->context($serviceAccount)
    ->issue('sk', 'Automated Pipeline Key');
```

### Team-Scoped Service Accounts

```php
// Admin creates a service account token for a specific team
$token = Bearer::for($admin)
    ->context($serviceAccount)
    ->boundary($team)
    ->issue('sk', 'Team CI/CD Key');
```

## Next Steps

- **[Authentication](authentication.md)** - Protecting routes and checking permissions
- **[Revocation & Rotation](revocation-rotation.md)** - Managing token lifecycle
- **[Derived Keys](derived-keys.md)** - Creating child tokens with restricted abilities
