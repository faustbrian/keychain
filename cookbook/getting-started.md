# Getting Started

Bearer provides Stripe-style typed API tokens with groups, environments, and audit logging for Laravel applications.

## Requirements

Bearer requires PHP 8.4+ and Laravel 11+.

## Installation

Install Bearer with composer:

```bash
composer require cline/bearer
```

## Add the Trait

Add Bearer's trait to your user model:

```php
use Cline\Bearer\Concerns\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens;
}
```

## Run Migrations

First publish the migrations into your app's `migrations` directory:

```bash
php artisan vendor:publish --tag="bearer-migrations"
```

Then run the migrations:

```bash
php artisan migrate
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="bearer-config"
```

### Morph Type Configuration

Bearer supports different polymorphic relationship types. Configure this **before** running migrations:

```php
// config/bearer.php
return [
    'database' => [
        // Primary key type: 'numeric' (bigint), 'uuid', 'ulid'
        'primary_key' => env('BEARER_PRIMARY_KEY', 'numeric'),

        // Morph type: 'numeric', 'uuid', 'ulid', 'string'
        'morph_type' => env('BEARER_MORPH_TYPE', 'numeric'),

        // Table names (customize if needed)
        'tables' => [
            'tokens' => 'personal_access_tokens',
            'groups' => 'token_groups',
            'audit_logs' => 'token_audit_logs',
        ],

        // Database connection (null = default)
        'connection' => env('BEARER_DB_CONNECTION'),
    ],
];
```

### Morph Type Options

| Type | ID Column | Best For |
|------|-----------|----------|
| `numeric` | `unsignedBigInteger` | Traditional Laravel apps with auto-incrementing IDs |
| `uuid` | `uuid` | Distributed systems, privacy-focused apps |
| `ulid` | `ulid` (26 chars) | Time-ordered distributed IDs |
| `string` | `string` | Legacy systems, external ID integration |

### User Model Configuration

Your User model must match the configured morph type:

```php
// For UUID:
use Illuminate\Database\Eloquent\Concerns\HasUuids;

class User extends Authenticatable
{
    use HasApiTokens;
    use HasUuids;

    public $incrementing = false;
    protected $keyType = 'string';
}

// For ULID:
use Illuminate\Database\Eloquent\Concerns\HasUlids;

class User extends Authenticatable
{
    use HasApiTokens;
    use HasUlids;

    public $incrementing = false;
    protected $keyType = 'string';
}
```

## Migrating from Sanctum

If you're migrating from Sanctum, add the required columns to your existing table:

```php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->string('type', 10)->default('sk')->after('name');
            $table->string('environment', 10)->default('test')->after('type');
            $table->foreignId('group_id')->nullable()->after('tokenable_id');
            $table->json('allowed_ips')->nullable();
            $table->json('allowed_domains')->nullable();
            $table->unsignedInteger('rate_limit')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('expires_at')->nullable();

            $table->index('type');
            $table->index('environment');
            $table->index('group_id');
        });

        Schema::create('token_groups', function (Blueprint $table) {
            $table->id();
            $table->morphs('tokenable');
            $table->string('name');
            $table->timestamps();
        });

        Schema::create('token_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('personal_access_token_id')->constrained()->cascadeOnDelete();
            $table->string('event', 50);
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamp('created_at');
        });
    }
};
```

## Index Optimization

For high-volume applications, consider these additional indexes:

```php
Schema::table('personal_access_tokens', function (Blueprint $table) {
    $table->index('token');
    $table->index(['tokenable_type', 'tokenable_id', 'revoked_at']);
    $table->index(['type', 'environment']);
    $table->index('expires_at');
});

Schema::table('token_audit_logs', function (Blueprint $table) {
    $table->index('event');
    $table->index('created_at');
    $table->index(['personal_access_token_id', 'event', 'created_at']);
});
```

## Using the Facade

Whenever you use the `Bearer` facade in your code, remember to add this line to your namespace imports:

```php
use Cline\Bearer\Facades\Bearer;
```

## Next Steps

- **[Basic Usage](basic-usage.md)** - Creating, validating, and managing tokens
- **[Authentication](authentication.md)** - Integrating with Laravel authentication
- **[Custom Token Types](custom-token-types.md)** - Defining typed tokens with abilities
