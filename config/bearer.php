<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/*
|--------------------------------------------------------------------------
| Bearer Token Management Configuration
|--------------------------------------------------------------------------
|
| This file defines the configuration for Bearer, a Laravel package for
| managing API tokens with multi-environment support, granular permissions,
| token groups, audit logging, and rate limiting. Bearer provides a
| comprehensive solution for API authentication with features like token
| rotation, revocation strategies, and multiple token type support.
|
*/

use Cline\Bearer\AuditDrivers\DatabaseAuditDriver;
use Cline\Bearer\AuditDrivers\NullAuditDriver;
use Cline\Bearer\AuditDrivers\SpatieActivityLogDriver;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\RevocationStrategies\CascadeDescendantsStrategy;
use Cline\Bearer\RevocationStrategies\CascadeStrategy;
use Cline\Bearer\RevocationStrategies\NoneStrategy;
use Cline\Bearer\RevocationStrategies\PartialCascadeStrategy;
use Cline\Bearer\RevocationStrategies\TimedStrategy;
use Cline\Bearer\RotationStrategies\DualValidStrategy;
use Cline\Bearer\RotationStrategies\GracePeriodStrategy;
use Cline\Bearer\RotationStrategies\ImmediateInvalidationStrategy;
use Cline\Bearer\TokenGenerators\RandomTokenGenerator;
use Cline\Bearer\TokenGenerators\SeamTokenGenerator;
use Cline\Bearer\TokenGenerators\UuidTokenGenerator;
use Cline\Bearer\TokenHashers\Sha256TokenHasher;
use Cline\Bearer\TokenHashers\Sha512TokenHasher;

return [
    /*
    |--------------------------------------------------------------------------
    | Primary Key Type
    |--------------------------------------------------------------------------
    |
    | This option controls the type of primary key used in Bearer's database
    | tables. You may use traditional auto-incrementing integers or choose
    | ULIDs or UUIDs for distributed systems or enhanced privacy.
    |
    | Supported: "id", "uuid", "ulid"
    |
    */

    'primary_key_type' => env('BEARER_PRIMARY_KEY_TYPE', 'id'),
    /*
    |--------------------------------------------------------------------------
    | Morph Type
    |--------------------------------------------------------------------------
    |
    | This option controls the type of polymorphic relationship columns used
    | for tokenable relationships in Bearer's database tables. This determines
    | how tokens are associated with different model types (users, teams, etc).
    |
    | Supported: "numeric", "uuid", "ulid", "string"
    |
    */

    'morph_type' => env('BEARER_MORPH_TYPE', 'numeric'),
    /*
    |--------------------------------------------------------------------------
    | Environments
    |--------------------------------------------------------------------------
    |
    | Bearer supports multi-environment token management, allowing you to
    | separate test and production tokens. This configuration defines which
    | environments are allowed and which is used by default when creating
    | new tokens. This enables safe testing without affecting production
    | API usage or rate limits.
    |
    */

    'environments' => [
        /*
        |--------------------------------------------------------------------------
        | Allowed Environments
        |--------------------------------------------------------------------------
        |
        | This array defines the valid environment values that can be assigned
        | to tokens. Typically, you'll want to separate 'test' and 'live'
        | environments to ensure development and testing activities don't
        | interfere with production systems.
        |
        */

        'allowed' => ['test', 'live'],
        /*
        |--------------------------------------------------------------------------
        | Default Environment
        |--------------------------------------------------------------------------
        |
        | This option specifies which environment will be used by default when
        | creating new tokens without explicitly specifying an environment.
        | Setting this to 'test' ensures that tokens are created in a safe
        | environment by default, reducing the risk of accidental production
        | token creation during development.
        |
        */

        'default' => env('BEARER_DEFAULT_ENVIRONMENT', 'test'),
    ],
    /*
    |--------------------------------------------------------------------------
    | Token Generation
    |--------------------------------------------------------------------------
    |
    | These options control how API tokens are generated. Bearer supports
    | multiple token generation strategies including Seam-style prefixed
    | tokens, UUIDs, and cryptographically secure random tokens. Each
    | generator provides different trade-offs between readability,
    | security, and compatibility.
    |
    */

    'generator' => [
        /*
        |--------------------------------------------------------------------------
        | Default Token Generator
        |--------------------------------------------------------------------------
        |
        | This option determines which token generator will be used by default
        | when creating new tokens. The Seam generator creates prefixed tokens
        | like 'sk_test_abc123' which are easy to identify and provide visual
        | distinction between token types and environments.
        |
        */

        'default' => env('BEARER_GENERATOR', 'seam'),
        /*
        |--------------------------------------------------------------------------
        | Available Token Generators
        |--------------------------------------------------------------------------
        |
        | Here you may define all available token generators that can be used
        | for creating API tokens. Each generator implements different token
        | formats:
        |
        | - seam: Creates prefixed tokens (e.g., sk_test_abc123) with visual
        |         distinction between token types and environments
        | - uuid: Generates UUIDs for tokens, useful for standard UUID-based
        |         systems and databases
        | - random: Creates cryptographically secure random tokens using
        |           Laravel's Str::random() helper
        |
        | You may add custom generators by implementing the TokenGenerator
        | contract and registering them here.
        |
        */

        'drivers' => [
            'seam' => SeamTokenGenerator::class,
            'uuid' => UuidTokenGenerator::class,
            'random' => RandomTokenGenerator::class,
        ],
    ],
    /*
    |--------------------------------------------------------------------------
    | Token Hashing
    |--------------------------------------------------------------------------
    |
    | These options control how API tokens are hashed for secure storage.
    | Bearer supports multiple hashing algorithms to balance security
    | requirements with performance needs. SHA-256 is the recommended default
    | for most applications.
    |
    */

    'hasher' => [
        /*
        |--------------------------------------------------------------------------
        | Default Token Hasher
        |--------------------------------------------------------------------------
        |
        | This option determines which hash algorithm will be used for storing
        | tokens in the database. SHA-256 provides excellent security and
        | performance for API token storage. SHA-512 offers stronger security
        | at the cost of longer hash values.
        |
        */

        'default' => env('BEARER_HASHER', 'sha256'),

        /*
        |--------------------------------------------------------------------------
        | Available Token Hashers
        |--------------------------------------------------------------------------
        |
        | Here you may define all available token hashers that can be used for
        | storing API tokens. Each hasher implements a different hash algorithm:
        |
        | - sha256: SHA-256 hashing (64 character hex output) - recommended
        | - sha512: SHA-512 hashing (128 character hex output) - stronger security
        |
        | You may add custom hashers by implementing the TokenHasher contract
        | and registering them here.
        |
        */

        'drivers' => [
            'sha256' => Sha256TokenHasher::class,
            'sha512' => Sha512TokenHasher::class,
        ],
    ],
    /*
    |--------------------------------------------------------------------------
    | Token Types
    |--------------------------------------------------------------------------
    |
    | Bearer supports multiple token types with different security levels
    | and use cases. Each token type can have its own generator, permissions,
    | and behavior. This configuration maps token type prefixes to their
    | implementation classes and optional custom generators.
    |
    */

    'types' => [
        /*
        |--------------------------------------------------------------------------
        | Secret Keys (sk)
        |--------------------------------------------------------------------------
        |
        | Secret keys are high-privilege tokens intended for server-to-server
        | communication. These tokens should never be exposed in client-side
        | code and typically have full API access. They are commonly used for
        | administrative operations, backend services, and trusted integrations.
        |
        */

        'sk' => [
            'name' => 'Secret',
            'prefix' => 'sk',
            'abilities' => ['*'],
            'expiration' => null, // never expires
            'rate_limit' => null, // unlimited
            'environments' => ['test', 'live'],
            'server_side_only' => true,
            'generator' => null, // uses default generator
        ],
        /*
        |--------------------------------------------------------------------------
        | Publishable Keys (pk)
        |--------------------------------------------------------------------------
        |
        | Publishable keys are designed to be safely embedded in client-side
        | applications such as mobile apps or JavaScript frontends. These tokens
        | typically have restricted permissions and are safe to expose publicly.
        | They're commonly used for read-only operations or public API endpoints.
        |
        */

        'pk' => [
            'name' => 'Publishable',
            'prefix' => 'pk',
            'abilities' => ['read'],
            'expiration' => 60 * 24 * 30, // 30 days in minutes
            'rate_limit' => 1000, // requests per minute
            'environments' => ['test', 'live'],
            'server_side_only' => false,
            'generator' => null, // uses default generator
        ],
        /*
        |--------------------------------------------------------------------------
        | Restricted Keys (rk)
        |--------------------------------------------------------------------------
        |
        | Restricted keys are tokens with limited scope and permissions. These
        | tokens are ideal for granting temporary or scoped access to specific
        | API resources without providing full API access. Use these for
        | integrations that only need access to specific endpoints or features.
        |
        */

        'rk' => [
            'name' => 'Restricted',
            'prefix' => 'rk',
            'abilities' => [],
            'expiration' => 60 * 24 * 365, // 1 year in minutes
            'rate_limit' => 100, // requests per minute
            'environments' => ['test', 'live'],
            'server_side_only' => true,
            'generator' => null, // uses default generator
        ],

        /*
        |--------------------------------------------------------------------------
        | Token Group Helper Mappings
        |--------------------------------------------------------------------------
        |
        | These mappings define which token types correspond to the convenience
        | helper methods on AccessTokenGroup models. This allows you to customize
        | which token type is returned by methods like secretKey(), publishableKey(),
        | and restrictedKey() when working with token groups.
        |
        */

        'group_helpers' => [
            'secret' => 'sk',
            'publishable' => 'pk',
            'restricted' => 'rk',
        ],
    ],
    /*
    |--------------------------------------------------------------------------
    | Audit Logging
    |--------------------------------------------------------------------------
    |
    | These options control how Bearer logs token usage and security events.
    | Audit logging provides a comprehensive trail of token operations including
    | creation, usage, rotation, and revocation. This is essential for security
    | compliance, debugging, and detecting suspicious activity.
    |
    */

    'audit' => [
        /*
        |--------------------------------------------------------------------------
        | Audit Driver
        |--------------------------------------------------------------------------
        |
        | This option determines which audit driver will be used to log token
        | events. The database driver stores events in a dedicated table, while
        | the Spatie Activity Log integration provides compatibility with
        | existing activity logging infrastructure. Use the null driver to
        | disable audit logging entirely.
        |
        */

        'driver' => env('BEARER_AUDIT_DRIVER', 'database'),
        /*
        |--------------------------------------------------------------------------
        | Available Audit Drivers
        |--------------------------------------------------------------------------
        |
        | Here you may configure all available audit drivers for logging token
        | events. Each driver provides different storage and integration options:
        |
        | - database: Stores audit logs in the access_token_audit_logs table with
        |            optional custom database connection
        | - spatie: Integrates with spatie/laravel-activitylog package for
        |          unified activity logging across your application
        | - null: Disables audit logging entirely for performance-critical
        |        applications that don't require audit trails
        |
        */

        'drivers' => [
            'database' => [
                'class' => DatabaseAuditDriver::class,
                'connection' => null, // null = default database connection
            ],
            'spatie' => [
                'class' => SpatieActivityLogDriver::class,
                'log_name' => 'bearer',
            ],
            'null' => [
                'class' => NullAuditDriver::class,
            ],
        ],
        /*
        |--------------------------------------------------------------------------
        | Log Token Usage
        |--------------------------------------------------------------------------
        |
        | When enabled, Bearer will log every API request made with a token.
        | This provides detailed visibility into token usage patterns and can
        | help identify unusual activity. Disable this in high-traffic
        | applications to reduce database writes and storage requirements.
        |
        */

        'log_usage' => true,
        /*
        |--------------------------------------------------------------------------
        | Audit Log Retention
        |--------------------------------------------------------------------------
        |
        | This option specifies how many days to retain audit log entries before
        | they become eligible for pruning. Configure the bearer:prune-audit-logs
        | command to run periodically to clean up old logs. Set to null to
        | retain logs indefinitely. The default is 90 days for most compliance
        | requirements.
        |
        */

        'retention_days' => 90,
    ],
    /*
    |--------------------------------------------------------------------------
    | Pruning Configuration
    |--------------------------------------------------------------------------
    |
    | These options control the default behavior of token pruning commands.
    | The expired_hours setting determines how long after expiration or
    | revocation a token must be before it's eligible for removal.
    |
    */

    'prune' => [
        'expired_hours' => 24,
    ],
    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | These options control rate limiting for API tokens. Bearer provides
    | per-token rate limiting with configurable limits per environment. This
    | helps prevent API abuse, ensures fair usage, and protects your
    | infrastructure from excessive requests.
    |
    */

    'rate_limiting' => [
        /*
        |--------------------------------------------------------------------------
        | Rate Limiting Enabled
        |--------------------------------------------------------------------------
        |
        | This option determines whether rate limiting is active for API tokens.
        | When enabled, each token will be subject to the configured rate limits
        | based on its environment. Disable this if you're using external rate
        | limiting solutions or don't require per-token rate limiting.
        |
        */

        'enabled' => true,
        /*
        |--------------------------------------------------------------------------
        | Cache Driver
        |--------------------------------------------------------------------------
        |
        | This option specifies which cache driver should be used for storing
        | rate limit counters. Setting this to null uses your application's
        | default cache driver. Consider using Redis or Memcached for optimal
        | performance in distributed systems.
        |
        */

        'cache_driver' => null, // null = default cache driver
        /*
        |--------------------------------------------------------------------------
        | Default Rate Limits
        |--------------------------------------------------------------------------
        |
        | These values define the default number of requests allowed per hour
        | for each environment. Test environment tokens typically have higher
        | limits to facilitate development and testing, while live environment
        | tokens have more conservative limits to protect production systems.
        |
        | These defaults can be overridden on a per-token basis when creating
        | or updating tokens.
        |
        */

        'defaults' => [
            'test' => 10000,
            'live' => 1000,
        ],
    ],
    /*
    |--------------------------------------------------------------------------
    | Revocation
    |--------------------------------------------------------------------------
    |
    | These options control what happens to related tokens when a parent token
    | is revoked. Bearer supports multiple revocation strategies including
    | cascading revocation for secret keys and isolated revocation for other
    | token types. This ensures appropriate security behavior when tokens are
    | compromised or no longer needed.
    |
    */

    'revocation' => [
        /*
        |--------------------------------------------------------------------------
        | Default Revocation Strategy
        |--------------------------------------------------------------------------
        |
        | This option determines the default behavior when revoking tokens
        | without specifying a strategy. The 'none' strategy only revokes the
        | specific token, while 'cascade' will also revoke all tokens in the
        | same group. The 'partial' strategy revokes only server-side tokens.
        |
        */

        'default' => env('BEARER_REVOCATION_STRATEGY', 'none'),

        /*
        |--------------------------------------------------------------------------
        | Available Revocation Strategies
        |--------------------------------------------------------------------------
        |
        | Here you may configure all available revocation strategies. Each
        | strategy provides different revocation behavior:
        |
        | - none: Only revokes the specific token
        | - cascade: Revokes all tokens in the same group
        | - partial: Revokes only server-side tokens (sk, rk) in the group
        | - timed: Schedules revocation after a delay period
        |
        | You may add custom strategies by implementing the RevocationStrategy
        | contract and registering them here.
        |
        */

        'drivers' => [
            'none' => [
                'class' => NoneStrategy::class,
            ],
            'cascade' => [
                'class' => CascadeStrategy::class,
            ],
            'cascade_descendants' => [
                'class' => CascadeDescendantsStrategy::class,
            ],
            'partial' => [
                'class' => PartialCascadeStrategy::class,
                'types' => ['sk', 'rk'], // Token types to revoke
            ],
            'timed' => [
                'class' => TimedStrategy::class,
                'delay_minutes' => 60, // Delay before revocation takes effect
            ],
        ],

        /*
        |--------------------------------------------------------------------------
        | Token Type Revocation Modes
        |--------------------------------------------------------------------------
        |
        | These options define which revocation strategy to use for each token
        | type when revoking without specifying a strategy. Secret keys use
        | cascade mode to ensure that when a master token is revoked, all
        | related tokens are also invalidated. Publishable and restricted
        | keys use 'none' mode as they typically don't have child tokens.
        |
        */

        'modes' => [
            'sk' => 'cascade',
            'pk' => 'none',
            'rk' => 'none',
        ],
    ],
    /*
    |--------------------------------------------------------------------------
    | Rotation
    |--------------------------------------------------------------------------
    |
    | Token rotation allows you to replace tokens with new ones whilst
    | maintaining a grace period where both tokens remain valid. This enables
    | zero-downtime token updates in production systems. Configure the
    | rotation mode and grace period to match your deployment practices.
    |
    */

    'rotation' => [
        /*
        |--------------------------------------------------------------------------
        | Default Rotation Strategy
        |--------------------------------------------------------------------------
        |
        | This option determines how token rotation is handled by default.
        | The 'immediate' strategy invalidates the old token immediately upon
        | rotation, whilst 'grace_period' keeps both tokens valid for a
        | configured duration to allow for gradual rollout.
        |
        */

        'default' => env('BEARER_ROTATION_STRATEGY', 'immediate'),

        /*
        |--------------------------------------------------------------------------
        | Available Rotation Strategies
        |--------------------------------------------------------------------------
        |
        | Here you may configure all available rotation strategies. Each
        | strategy provides different rotation behavior:
        |
        | - immediate: Old token is invalidated immediately
        | - grace_period: Old token remains valid for a configured duration
        | - dual_valid: Both tokens remain valid until old one expires
        |
        | You may add custom strategies by implementing the RotationStrategy
        | contract and registering them here.
        |
        */

        'drivers' => [
            'immediate' => [
                'class' => ImmediateInvalidationStrategy::class,
            ],
            'grace_period' => [
                'class' => GracePeriodStrategy::class,
                'grace_period_minutes' => 60,
            ],
            'dual_valid' => [
                'class' => DualValidStrategy::class,
            ],
        ],

        /*
        |--------------------------------------------------------------------------
        | Grace Period Duration (Deprecated)
        |--------------------------------------------------------------------------
        |
        | This option is deprecated and will be removed in a future version.
        | Please use the 'grace_period_minutes' option in the grace_period
        | driver configuration above instead.
        |
        */

        'grace_period_minutes' => 60,
    ],
    /*
    |--------------------------------------------------------------------------
    | Token Derivation
    |--------------------------------------------------------------------------
    |
    | Token derivation allows parent tokens to create child tokens with
    | inherited restrictions but more limited abilities and lifespans. This
    | enables hierarchical token structures where resellers can issue customer
    | tokens without those customers needing full accounts in your system.
    |
    */

    'derivation' => [
        /*
        |--------------------------------------------------------------------------
        | Enable Token Derivation
        |--------------------------------------------------------------------------
        |
        | This option controls whether token derivation is enabled. When enabled,
        | tokens can derive child tokens using the Ancestry hierarchical system.
        | Disable this if you don't need hierarchical token relationships.
        |
        */

        'enabled' => env('BEARER_DERIVATION_ENABLED', true),

        /*
        |--------------------------------------------------------------------------
        | Maximum Derivation Depth
        |--------------------------------------------------------------------------
        |
        | This option controls the maximum depth allowed for token derivation
        | hierarchies. A depth of 3 allows: master -> reseller -> customer.
        | Set to null for unlimited depth (not recommended for production).
        |
        */

        'max_depth' => env('BEARER_MAX_DERIVATION_DEPTH', 3),

        /*
        |--------------------------------------------------------------------------
        | Hierarchy Type
        |--------------------------------------------------------------------------
        |
        | This option specifies the Ancestry hierarchy type identifier used for
        | token derivation relationships. This allows you to maintain multiple
        | separate hierarchy types if needed.
        |
        */

        'hierarchy_type' => 'token_derivation',

        /*
        |--------------------------------------------------------------------------
        | Inherit Restrictions
        |--------------------------------------------------------------------------
        |
        | When enabled, derived tokens inherit IP and domain restrictions from
        | their parent tokens. Child tokens can add additional restrictions but
        | cannot remove parent restrictions.
        |
        */

        'inherit_restrictions' => true,

        /*
        |--------------------------------------------------------------------------
        | Enforce Ability Subset
        |--------------------------------------------------------------------------
        |
        | When enabled, derived tokens must have abilities that are a subset of
        | their parent token's abilities. This ensures child tokens cannot have
        | more permissions than their parents.
        |
        */

        'enforce_ability_subset' => true,

        /*
        |--------------------------------------------------------------------------
        | Enforce Expiration
        |--------------------------------------------------------------------------
        |
        | When enabled, derived tokens must expire at or before their parent
        | token's expiration. This ensures child tokens cannot outlive their
        | parents.
        |
        */

        'enforce_expiration' => true,
    ],
    /*
    |--------------------------------------------------------------------------
    | Eloquent Models
    |--------------------------------------------------------------------------
    |
    | When using Bearer's database features, these models are used to
    | interact with the database. You may extend these models with your own
    | implementations whilst ensuring they extend the base classes provided
    | by Bearer. This allows you to customise model behavior whilst
    | maintaining compatibility with Bearer's internal operations.
    |
    */

    'models' => [
        /*
        |--------------------------------------------------------------------------
        | Personal Access Token Model
        |--------------------------------------------------------------------------
        |
        | This model is used to retrieve and manage API tokens from the database.
        | The model you specify must extend the `Cline\Bearer\Database\Models\AccessToken`
        | class. This allows you to customise the token model behavior whilst
        | maintaining compatibility with Bearer's internal operations.
        |
        */

        'access_token' => AccessToken::class,
        /*
        |--------------------------------------------------------------------------
        | Token Group Model
        |--------------------------------------------------------------------------
        |
        | This model is used to retrieve and manage token groups from the database.
        | The model you specify must extend the `Cline\Bearer\Database\Models\AccessTokenGroup`
        | class. Groups allow you to organise multiple tokens under a single
        | logical unit for easier management and batch operations.
        |
        */

        'access_token_group' => AccessTokenGroup::class,
        /*
        |--------------------------------------------------------------------------
        | Token Audit Log Model
        |--------------------------------------------------------------------------
        |
        | This model is used to retrieve token audit log entries from the database.
        | The model you specify must extend the `Cline\Bearer\Database\Models\AccessTokenAuditLog`
        | class. This model maintains an audit trail of all token operations,
        | including creation, usage, rotation, and revocation events.
        |
        */

        'access_token_audit_log' => AccessTokenAuditLog::class,
    ],
    /*
    |--------------------------------------------------------------------------
    | Database Table Names
    |--------------------------------------------------------------------------
    |
    | When using Bearer's database features, these table names are used to
    | store your API tokens, token groups, and audit logs. These table names
    | are used by both the migrations and Eloquent models. You may customise
    | these if you need to avoid naming conflicts with existing tables.
    |
    */

    'table_names' => [
        /*
        |--------------------------------------------------------------------------
        | Personal Access Tokens Table
        |--------------------------------------------------------------------------
        |
        | This table stores API token definitions, hashed values, permissions,
        | rate limits, and expiration settings with polymorphic tokenable
        | support. It serves as the central repository for all API tokens
        | managed by Bearer.
        |
        */

        'access_tokens' => 'access_tokens',
        /*
        |--------------------------------------------------------------------------
        | Token Groups Table
        |--------------------------------------------------------------------------
        |
        | This table stores named groups of related tokens with optional
        | metadata for batch operations. Groups allow you to organise tokens
        | by purpose, integration, or environment for easier management.
        |
        */

        'access_token_groups' => 'access_token_groups',
        /*
        |--------------------------------------------------------------------------
        | Token Audit Logs Table
        |--------------------------------------------------------------------------
        |
        | This table stores audit log entries for token operations including
        | creation, usage, rotation, revocation, and security events. This
        | provides a comprehensive audit trail for compliance and debugging.
        |
        */

        'access_token_audit_logs' => 'access_token_audit_logs',
    ],
    /*
    |--------------------------------------------------------------------------
    | Guard Configuration
    |--------------------------------------------------------------------------
    |
    | This option specifies which authentication guards should be used when
    | authenticating requests with Bearer tokens. By default, the 'web'
    | guard is used, but you may specify multiple guards or alternative
    | guards based on your authentication requirements.
    |
    */

    'guard' => ['web'],
    /*
    |--------------------------------------------------------------------------
    | Stateful Domains
    |--------------------------------------------------------------------------
    |
    | This option defines which domains are considered "stateful" for token
    | authentication purposes. Requests from these domains may use session-based
    | authentication in addition to token authentication. This is particularly
    | useful for first-party applications that need both session and token
    | authentication capabilities.
    |
    */

    'stateful' => explode(',', env('BEARER_STATEFUL_DOMAINS', sprintf(
        '%s%s',
        'localhost,localhost:3000,127.0.0.1,127.0.0.1:8000,::1',
        env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : ''
    ))),
    /*
    |--------------------------------------------------------------------------
    | Session Cookie Settings
    |--------------------------------------------------------------------------
    |
    | These options control the session cookie settings for stateful frontend
    | requests. The http_only setting ensures cookies are not accessible via
    | JavaScript, and same_site controls cross-site cookie behavior for CSRF
    | protection. Use 'strict' for maximum security or 'none' for cross-origin
    | authentication (requires HTTPS).
    |
    | Supported same_site values: 'lax', 'strict', 'none'
    |
    */

    'session' => [
        'http_only' => true,
        'same_site' => 'lax',
    ],
    /*
    |--------------------------------------------------------------------------
    | Stateful Middleware Stack
    |--------------------------------------------------------------------------
    |
    | These options allow you to customize the middleware stack used for
    | stateful frontend requests. By default, Bearer uses Laravel's standard
    | session and CSRF middleware. You can override these to use custom
    | middleware classes or set to null to disable specific middleware.
    |
    */

    'middleware' => [
        'encrypt_cookies' => \Illuminate\Cookie\Middleware\EncryptCookies::class,
        'add_queued_cookies' => \Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse::class,
        'start_session' => \Illuminate\Session\Middleware\StartSession::class,
        'validate_csrf_token' => \Illuminate\Foundation\Http\Middleware\VerifyCsrfToken::class,
        'authenticate_session' => null, // null = disabled by default
    ],
    /*
    |--------------------------------------------------------------------------
    | Token Expiration
    |--------------------------------------------------------------------------
    |
    | This option specifies the global default expiration time for tokens
    | in minutes. Individual token types can override this value in their
    | configuration. Set to null to create tokens that never expire by
    | default. Note that tokens without expiration pose a security risk
    | if compromised, so it's recommended to use reasonable expiration
    | times for production environments.
    |
    */

    'expiration' => null, // null = no expiration by default
    /*
    |--------------------------------------------------------------------------
    | Polymorphic Key Mapping
    |--------------------------------------------------------------------------
    |
    | This option allows you to specify which column should be used as the
    | foreign key for each model in polymorphic relationships. This is
    | particularly useful when different models in your application use
    | different primary key column names, which is common in legacy systems
    | or when using ULIDs and UUIDs alongside traditional auto-incrementing
    | integer keys.
    |
    | For example, if your User model uses 'id' but your Organization model
    | uses 'ulid', you can map each model to its appropriate key column here.
    | Bearer will then use the correct column when storing foreign keys.
    |
    | Note: You may only configure either 'morphKeyMap' or 'enforceMorphKeyMap',
    | not both. Choose the non-enforced variant if you want to allow models
    | without explicit mappings to use their default primary key.
    |
    */

    'morphKeyMap' => [
        // App\Models\User::class => 'id',
        // App\Models\Organization::class => 'id',
    ],
    /*
    |--------------------------------------------------------------------------
    | Enforced Polymorphic Key Mapping
    |--------------------------------------------------------------------------
    |
    | This option works identically to 'morphKeyMap' above, but enables strict
    | enforcement of your key mappings. When configured, any model referenced
    | in a polymorphic relationship without an explicit mapping defined here
    | will throw a MorphKeyViolationException.
    |
    | This enforcement is useful in production environments where you want to
    | ensure all models participating in polymorphic relationships have been
    | explicitly configured, preventing potential bugs from unmapped models.
    |
    | Note: Only configure either 'morphKeyMap' or 'enforceMorphKeyMap'. Using
    | both simultaneously is not supported. Choose this enforced variant when
    | you want strict type safety for your polymorphic relationships.
    |
    */

    'enforceMorphKeyMap' => [
        // App\Models\User::class => 'id',
        // App\Models\Organization::class => 'id',
    ],
];

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //
// Here endeth thy configuration, noble developer!                            //
// Beyond: code so wretched, even wyrms learned the scribing arts.            //
// Forsooth, they but penned "// TODO: remedy ere long"                       //
// Three realms have fallen since...                                          //
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //
//                                                  .~))>>                    //
//                                                 .~)>>                      //
//                                               .~))))>>>                    //
//                                             .~))>>             ___         //
//                                           .~))>>)))>>      .-~))>>         //
//                                         .~)))))>>       .-~))>>)>          //
//                                       .~)))>>))))>>  .-~)>>)>              //
//                   )                 .~))>>))))>>  .-~)))))>>)>             //
//                ( )@@*)             //)>))))))  .-~))))>>)>                 //
//              ).@(@@               //))>>))) .-~))>>)))))>>)>               //
//            (( @.@).              //))))) .-~)>>)))))>>)>                   //
//          ))  )@@*.@@ )          //)>))) //))))))>>))))>>)>                 //
//       ((  ((@@@.@@             |/))))) //)))))>>)))>>)>                    //
//      )) @@*. )@@ )   (\_(\-\b  |))>)) //)))>>)))))))>>)>                   //
//    (( @@@(.@(@ .    _/`-`  ~|b |>))) //)>>)))))))>>)>                      //
//     )* @@@ )@*     (@)  (@) /\b|))) //))))))>>))))>>                       //
//   (( @. )@( @ .   _/  /    /  \b)) //))>>)))))>>>_._                       //
//    )@@ (@@*)@@.  (6///6)- / ^  \b)//))))))>>)))>>   ~~-.                   //
// ( @jgs@@. @@@.*@_ VvvvvV//  ^  \b/)>>))))>>      _.     `bb                //
//  ((@@ @@@*.(@@ . - | o |' \ (  ^   \b)))>>        .'       b`,             //
//   ((@@).*@@ )@ )   \^^^/  ((   ^  ~)_        \  /           b `,           //
//     (@@. (@@ ).     `-'   (((   ^    `\ \ \ \ \|             b  `.         //
//       (*.@*              / ((((        \| | |  \       .       b `.        //
//                         / / (((((  \    \ /  _.-~\     Y,      b  ;        //
//                        / / / (((((( \    \.-~   _.`" _.-~`,    b  ;        //
//                       /   /   `(((((()    )    (((((~      `,  b  ;        //
//                     _/  _/      `"""/   /'                  ; b   ;        //
//                 _.-~_.-~           /  /'              _.'~bb _.'         //
//               ((((~~              / /'              _.'~bb.--~             //
//                                  ((((          __.-~bb.-~                  //
//                                              .'  b .~~                     //
//                                              :bb ,'                        //
//                                              ~~~~                          //
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ //
