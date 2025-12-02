# Bearer - Feature Scope

## Token Types
- Configurable types (sk/pk/rk/custom) with prefixes via registry/strategies

## Token Groups
- Link related tokens (sk↔pk↔rk) for cross-validation queries

## Morph Support
- Configurable migrations: numeric, uuid, ulid, string morphs

## Environment Column
- `test`/`live` (or custom) with configurable allowed values

## Abilities/Scopes
- Sanctum-style with per-type configurable defaults

## Expiration
- Per-type configurable defaults

## Rate Limiting
- Configurable per type AND per environment

## Revocation
- Cascade strategies: full/partial/time-based, configurable per group
- When revoking sk, should pk/rk in same group also revoke? Configurable

## Rotation
- Rotation + invalidation strategies for replaced tokens
- Support rotation and invalidation strategies for full/partial/time-based/etc.

## Audit Logging
- Driver-based: default table, Spatie Activity Log, custom
- Logging for all token types with strategies

## Usage Tracking
- Full historical log + last_used_at (via audit driver)
- Historical tracking, not just last timestamp like Sanctum

## IP/Domain Restrictions
- Stripe-style, especially for pk tokens
- Follow Stripe functionality as close as possible

## Token Metadata
- Custom JSON data per token

## Auth Guards
- Sanctum-style guards adapted for typed tokens

---

# Implementation Plan

## Phase 1: Foundation (Skeleton + Core Structure)

### 1.1 Package Setup
- [ ] Copy skeleton-php to bearer directory
- [ ] Run configure.sh with: name=bearer, namespace=Cline\Bearer
- [ ] Update composer.json dependencies (illuminate/*, spatie/laravel-package-tools)
- [ ] Create directory structure following Toggl/Warden patterns

### 1.2 Directory Structure
```
src/
├── Concerns/
│   └── HasApiTokens.php              # Trait for tokenable models
├── Conductors/
│   ├── TokenIssuanceConductor.php    # Fluent API for creating tokens
│   ├── TokenRevocationConductor.php  # Fluent API for revoking tokens
│   ├── TokenRotationConductor.php    # Fluent API for rotating tokens
│   ├── TokenGroupConductor.php       # Fluent API for group operations
│   └── TokenQueryConductor.php       # Fluent API for querying tokens
├── Console/Commands/
│   ├── PruneExpiredCommand.php       # Prune expired tokens
│   └── PruneAuditLogsCommand.php     # Prune old audit logs
├── Contracts/
│   ├── HasAbilities.php              # Token abilities interface
│   ├── HasApiTokens.php              # Tokenable model interface
│   ├── TokenType.php                 # Token type interface
│   ├── TokenGenerator.php            # Token generation strategy interface
│   ├── AuditDriver.php               # Audit logging driver interface
│   ├── RevocationStrategy.php        # Revocation strategy interface
│   └── RotationStrategy.php          # Rotation strategy interface
├── Database/
│   ├── Concerns/
│   │   ├── HasPrimaryKeyType.php     # Primary key type trait
│   │   └── HasMorphType.php          # Morph type trait
│   ├── Models/
│   │   ├── PersonalAccessToken.php   # Main token model
│   │   ├── TokenGroup.php            # Token group model
│   │   ├── TokenAuditLog.php         # Audit log model
│   │   └── TokenUsageLog.php         # Usage tracking model
│   └── ModelRegistry.php             # Model class resolution
├── Enums/
│   ├── MorphType.php                 # numeric/uuid/ulid/string
│   ├── PrimaryKeyType.php            # id/ulid/uuid
│   ├── Environment.php               # test/live (configurable)
│   ├── AuditEvent.php                # created/used/revoked/rotated
│   └── RevocationStrategy.php        # none/cascade/partial/timed
├── Events/
│   ├── TokenAuthenticated.php        # Token used for auth
│   ├── TokenCreated.php              # Token issued
│   ├── TokenRevoked.php              # Token revoked
│   ├── TokenRotated.php              # Token rotated
│   └── TokenGroupCreated.php         # Group created
├── Exceptions/
│   ├── InvalidTokenTypeException.php
│   ├── InvalidEnvironmentException.php
│   ├── TokenExpiredException.php
│   ├── TokenRevokedException.php
│   ├── DomainRestrictionException.php
│   ├── IpRestrictionException.php
│   ├── RateLimitExceededException.php
│   └── InvalidConfigurationException.php
├── Facades/
│   └── Bearer.php
├── Guards/
│   └── BearerGuard.php             # Auth guard implementation
├── Http/
│   └── Middleware/
│       ├── CheckAbilities.php
│       ├── CheckForAnyAbility.php
│       ├── CheckTokenType.php        # Require specific token type
│       ├── CheckEnvironment.php      # Require specific environment
│       └── EnsureFrontendRequestsAreStateful.php
├── AuditDrivers/
│   ├── DatabaseAuditDriver.php       # Default: our tables
│   ├── SpatieActivityLogDriver.php   # Integration with spatie/laravel-activitylog
│   └── NullAuditDriver.php           # No-op for testing
├── RevocationStrategies/
│   ├── NoneStrategy.php              # Revoke only specified token
│   ├── CascadeStrategy.php           # Revoke entire group
│   ├── PartialCascadeStrategy.php    # Revoke specific types in group
│   └── TimedStrategy.php             # Delayed revocation
├── RotationStrategies/
│   ├── ImmediateInvalidationStrategy.php
│   ├── GracePeriodStrategy.php       # Old token valid for X time
│   └── DualValidStrategy.php         # Both valid until explicit revoke
├── Support/
│   ├── PrimaryKeyGenerator.php
│   └── PrimaryKeyValue.php
├── TokenGenerators/
│   ├── TokenGeneratorRegistry.php    # Register/resolve generators
│   ├── SeamTokenGenerator.php        # Default: Seam/Stripe style (prefix_env_base58)
│   ├── UuidTokenGenerator.php        # UUID-based tokens
│   └── RandomTokenGenerator.php      # Simple random string
├── TokenTypes/
│   ├── TokenTypeRegistry.php         # Register/resolve token types
│   ├── SecretTokenType.php           # sk_* - server-side only
│   ├── PublishableTokenType.php      # pk_* - client-safe
│   └── RestrictedTokenType.php       # rk_* - microservices
├── Bearer.php                      # Main manager class
├── BearerManager.php               # Multi-guard manager
├── NewAccessToken.php                # DTO for newly created tokens
├── TransientToken.php                # In-memory token for testing
└── BearerServiceProvider.php
```

## Phase 2: Core Models & Database

### 2.1 Migrations
- [ ] `create_bearer_tables` migration with:
  - `personal_access_tokens` table (configurable morph types)
  - `token_groups` table (linking related tokens)
  - `token_audit_logs` table (historical tracking)
  - `token_usage_logs` table (request history)

### 2.2 Token Model Schema
```php
// personal_access_tokens
- id/ulid/uuid (configurable)
- tokenable_type, tokenable_id (configurable morphs)
- group_id (nullable, FK to token_groups)
- type (string: sk/pk/rk/custom)
- environment (string: test/live/custom)
- name (string)
- token (string, hashed)
- prefix (string, stored for quick lookup: sk_test_)
- abilities (json)
- metadata (json, nullable)
- allowed_ips (json, nullable)
- allowed_domains (json, nullable)
- rate_limit_per_minute (int, nullable)
- last_used_at (timestamp, nullable)
- expires_at (timestamp, nullable)
- revoked_at (timestamp, nullable)
- created_at, updated_at
```

### 2.3 Token Group Schema
```php
// token_groups
- id/ulid/uuid (configurable)
- owner_type, owner_id (polymorphic to user/team)
- name (string, nullable)
- metadata (json, nullable)
- created_at, updated_at
```

### 2.4 Audit Log Schema
```php
// token_audit_logs
- id/ulid/uuid
- token_id (FK)
- event (enum: created/authenticated/revoked/rotated/failed)
- ip_address (string, nullable)
- user_agent (string, nullable)
- metadata (json, nullable)
- created_at
```

## Phase 3: Token Types & Generation

### 3.1 Token Type System
- [ ] `TokenTypeRegistry` - register/resolve token types
- [ ] `TokenType` interface with:
  - `prefix()` - e.g., 'sk', 'pk', 'rk'
  - `defaultAbilities()` - default scopes
  - `defaultExpiration()` - default TTL
  - `defaultRateLimit()` - default rate limit
  - `allowedEnvironments()` - which envs this type can be used in
  - `isServerSideOnly()` - should never be exposed to client

### 3.2 Token Generation Strategies
- [ ] `TokenGenerator` interface with:
  - `generate(string $type, string $environment): string`
  - `parse(string $token): ?TokenComponents` (extract type/env/secret)
  - `hash(string $token): string`
  - `verify(string $token, string $hash): bool`
- [ ] `SeamTokenGenerator` (default): `{prefix}_{env}_{base58}` (e.g., `sk_test_EXAMPLE1234567890abcdef`)
- [ ] `UuidTokenGenerator`: `{prefix}_{env}_{uuid}` (e.g., `sk_test_550e8400-e29b-41d4-a716-446655440000`)
- [ ] `RandomTokenGenerator`: `{prefix}_{env}_{random40}` (Sanctum-style)
- [ ] Configurable per token type or globally
- [ ] Store hash, return plaintext only on creation

## Phase 4: Token Groups & Linking

### 4.1 Group Management
- [ ] Create groups when issuing related tokens
- [ ] Query related tokens: `$token->group->tokens`
- [ ] Find sibling by type: `$token->sibling('sk')` or `$token->secretKey()`
- [ ] Fluent API: `Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'])`

### 4.2 Cross-Token Validation
- [ ] Given pk, find corresponding sk for server-side validation
- [ ] `Bearer::findRelated($pkToken, 'sk')`

## Phase 5: Auth Guards & Middleware

### 5.1 Guard Implementation
- [ ] Extend Sanctum's guard pattern
- [ ] Support type-specific guards: `auth:bearer-sk`, `auth:bearer-pk`
- [ ] Parse token prefix to determine type before lookup
- [ ] Validate environment matches config

### 5.2 Middleware
- [ ] `CheckAbilities` - from Sanctum
- [ ] `CheckTokenType` - require specific token type
- [ ] `CheckEnvironment` - require test/live environment
- [ ] `EnsureFrontendRequestsAreStateful` - from Sanctum

## Phase 6: Audit Logging & Usage Tracking

### 6.1 Audit Driver System
- [ ] `AuditDriver` interface
- [ ] `DatabaseAuditDriver` - default, our tables
- [ ] `SpatieActivityLogDriver` - spatie/laravel-activitylog integration
- [ ] `NullAuditDriver` - no-op for testing
- [ ] Configurable via `config('bearer.audit.driver')`

### 6.2 Events to Log
- [ ] Token created
- [ ] Token authenticated (every request)
- [ ] Token revoked
- [ ] Token rotated
- [ ] Authentication failed (rate limit, expired, revoked, ip/domain)

### 6.3 Usage Analytics
- [ ] Track: timestamp, IP, user agent, endpoint (optional)
- [ ] Update `last_used_at` on token (like Sanctum)
- [ ] Full history in audit log

## Phase 7: Revocation & Rotation

### 7.1 Revocation Strategies
- [ ] `RevocationStrategy` interface
- [ ] `NoneStrategy` - only specified token
- [ ] `CascadeStrategy` - entire group
- [ ] `PartialCascadeStrategy` - specific types (e.g., revoke sk revokes rk but not pk)
- [ ] `TimedStrategy` - schedule revocation for future
- [ ] Configurable default per token type

### 7.2 Rotation Strategies
- [ ] `RotationStrategy` interface
- [ ] `ImmediateInvalidationStrategy` - old token invalid immediately
- [ ] `GracePeriodStrategy` - old token valid for X minutes/hours
- [ ] `DualValidStrategy` - both valid until explicit revocation
- [ ] Create new token, handle old based on strategy

## Phase 8: Rate Limiting

### 8.1 Configuration
- [ ] Per token type default: `config('bearer.types.sk.rate_limit')`
- [ ] Per environment: `config('bearer.environments.test.rate_limit')`
- [ ] Per token override: `metadata.rate_limit_per_minute`
- [ ] Resolution order: token > type+env > type > env > global

### 8.2 Implementation
- [ ] Use Laravel's RateLimiter
- [ ] Key format: `bearer:{token_id}` or `bearer:{type}:{env}:{tokenable}`
- [ ] Throw `RateLimitExceededException` with retry-after

## Phase 9: IP & Domain Restrictions

### 9.1 IP Restrictions
- [ ] `allowed_ips` JSON column on token
- [ ] Support CIDR notation: `192.168.1.0/24`
- [ ] Validate on authentication
- [ ] Throw `IpRestrictionException`

### 9.2 Domain Restrictions (for pk tokens)
- [ ] `allowed_domains` JSON column
- [ ] Validate `Origin` or `Referer` header
- [ ] Wildcard support: `*.example.com`
- [ ] Throw `DomainRestrictionException`

## Phase 10: Configuration

### 10.1 Config Structure
```php
return [
    // Primary key type for tables
    'primary_key_type' => env('BEARER_PRIMARY_KEY_TYPE', 'id'),

    // Morph type for polymorphic relations
    'morph_type' => env('BEARER_MORPH_TYPE', 'morph'),

    // Environments
    'environments' => [
        'allowed' => ['test', 'live'],
        'default' => env('BEARER_DEFAULT_ENV', 'test'),
        'rate_limits' => [
            'test' => 1000,
            'live' => 100,
        ],
    ],

    // Token generation
    'generator' => [
        'default' => env('BEARER_GENERATOR', 'seam'),
        'drivers' => [
            'seam' => SeamTokenGenerator::class,    // Stripe/Seam style base58
            'uuid' => UuidTokenGenerator::class,    // UUID-based
            'random' => RandomTokenGenerator::class, // Sanctum-style random
        ],
    ],

    // Token types
    'types' => [
        'sk' => [
            'class' => SecretTokenType::class,
            'prefix' => 'sk',
            'name' => 'Secret',
            'generator' => null, // use default, or specify 'seam', 'uuid', etc.
            'server_side_only' => true,
            'default_abilities' => ['*'],
            'default_expiration' => null, // never
            'default_rate_limit' => null, // unlimited
        ],
        'pk' => [
            'class' => PublishableTokenType::class,
            'prefix' => 'pk',
            'name' => 'Publishable',
            'generator' => null,
            'server_side_only' => false,
            'default_abilities' => ['read'],
            'default_expiration' => 60 * 24 * 30, // 30 days
            'default_rate_limit' => 1000,
        ],
        'rk' => [
            'class' => RestrictedTokenType::class,
            'prefix' => 'rk',
            'name' => 'Restricted',
            'generator' => null,
            'server_side_only' => true,
            'default_abilities' => [],
            'default_expiration' => 60 * 24 * 365, // 1 year
            'default_rate_limit' => 100,
        ],
    ],

    // Audit logging
    'audit' => [
        'driver' => env('BEARER_AUDIT_DRIVER', 'database'),
        'drivers' => [
            'database' => [
                'connection' => null,
            ],
            'spatie' => [
                'log_name' => 'bearer',
            ],
            'null' => [],
        ],
        'log_usage' => true,
        'retention_days' => 90,
    ],

    // Revocation
    'revocation' => [
        'default_strategy' => 'none',
        'strategies' => [
            'sk' => 'cascade', // revoking sk cascades to group
            'pk' => 'none',
            'rk' => 'none',
        ],
    ],

    // Rotation
    'rotation' => [
        'default_strategy' => 'immediate',
        'grace_period_minutes' => 60,
    ],

    // Models (customizable)
    'models' => [
        'personal_access_token' => PersonalAccessToken::class,
        'token_group' => TokenGroup::class,
        'token_audit_log' => TokenAuditLog::class,
    ],

    // Table names
    'table_names' => [
        'personal_access_tokens' => 'personal_access_tokens',
        'token_groups' => 'token_groups',
        'token_audit_logs' => 'token_audit_logs',
    ],

    // Guard configuration
    'guard' => [
        'web' => [], // fallback guards for stateful requests
    ],

    // Expiration (global, overridden by type config)
    'expiration' => null,
];
```

## Phase 11: Service Provider & Facade

### 11.1 Service Provider
- [ ] Register BearerManager singleton
- [ ] Register TokenTypeRegistry
- [ ] Register AuditDriver based on config
- [ ] Configure auth guard
- [ ] Publish config, migrations
- [ ] Register commands

### 11.2 Facade
- [ ] `Bearer::for($user)->issue('sk')`
- [ ] `Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'])`
- [ ] `Bearer::revoke($token)`
- [ ] `Bearer::rotate($token)`
- [ ] `Bearer::findByPrefix('sk_test_abc123')`

## Phase 12: HasApiTokens Trait

### 12.1 Methods
```php
trait HasApiTokens
{
    public function tokens(): MorphMany;
    public function tokenGroups(): MorphMany;
    public function createToken(string $type, string $name, array $abilities = []): NewAccessToken;
    public function createTokenGroup(array $types, string $name, array $abilities = []): TokenGroup;
    public function currentAccessToken(): ?PersonalAccessToken;
    public function withAccessToken(PersonalAccessToken $token): static;
    public function tokenCan(string $ability): bool;
    public function tokenIs(string $type): bool; // Check current token type
    public function tokenEnvironment(): ?string; // Get current token environment
}
```

## Phase 13: Testing

### 13.1 Test Categories
- [ ] Unit tests for token generation
- [ ] Unit tests for token type registry
- [ ] Unit tests for revocation/rotation strategies
- [ ] Feature tests for auth guard
- [ ] Feature tests for middleware
- [ ] Feature tests for token groups
- [ ] Feature tests for audit logging
- [ ] Feature tests for rate limiting
- [ ] Feature tests for IP/domain restrictions

### 13.2 Test Helpers
- [ ] `Bearer::actingAs($user, ['abilities'], 'sk')`
- [ ] Factories for tokens, groups, audit logs

## Implementation Order

1. **Foundation**: Skeleton setup, directory structure, config
2. **Core Models**: Token, Group, migrations (configurable morphs)
3. **Token Types**: Registry, generator, prefix system
4. **Token Groups**: Linking, sibling queries
5. **Auth Guard**: Basic authentication flow
6. **HasApiTokens Trait**: User integration
7. **Middleware**: Abilities, type checking
8. **Audit Logging**: Driver system, usage tracking
9. **Revocation**: Strategies, cascade logic
10. **Rotation**: Strategies, grace periods
11. **Rate Limiting**: Per type/env/token
12. **IP/Domain**: Restrictions, validation
13. **Commands**: Prune expired, prune audit logs
14. **Tests**: Comprehensive coverage
