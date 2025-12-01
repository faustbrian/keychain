<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Enums\MorphType;
use Cline\Bearer\Enums\PrimaryKeyType;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Migration for creating Bearer token management database tables.
 *
 * This migration creates three tables for the Bearer API token management system:
 * - access_token_groups: stores token groups for organizational purposes
 * - access_tokens: stores API token records with metadata and restrictions
 * - access_token_audit_logs: stores audit trail of token operations
 *
 * The primary key type (ID, ULID, UUID) and morph type (numeric, uuid, ulid, string)
 * are configured via the bearer.primary_key_type and bearer.morph_type
 * configuration options to support different application requirements.
 *
 * @see config/bearer.php
 */
return new class() extends Migration
{
    /**
     * Run the migrations to create token management tables.
     *
     * Creates the database schema for storing API tokens, token groups,
     * and audit logs with support for configurable primary key types and morph types.
     */
    public function up(): void
    {
        $primaryKeyType = PrimaryKeyType::tryFrom(config('bearer.primary_key_type', 'id')) ?? PrimaryKeyType::Id;
        $morphType = MorphType::tryFrom(config('bearer.morph_type', 'string')) ?? MorphType::String;

        $connection = config('bearer.connection') ?? config('database.default');
        $useJsonb = DB::connection($connection)->getDriverName() === 'pgsql';

        $tableNames = config('bearer.table_names', [
            'access_tokens' => 'access_tokens',
            'access_token_groups' => 'access_token_groups',
            'access_token_audit_logs' => 'access_token_audit_logs',
        ]);

        // Create access_token_groups table first (referenced by tokens)
        Schema::create($tableNames['access_token_groups'], function (Blueprint $table) use ($primaryKeyType, $morphType, $useJsonb): void {
            // Primary key based on config
            $this->addPrimaryKey($table, $primaryKeyType);

            // Polymorphic owner (user/team)
            $this->addMorphColumns($table, 'owner', $morphType);

            $table->string('name')->nullable();
            $useJsonb
                ? $table->jsonb('metadata')->nullable()
                : $table->json('metadata')->nullable();
            $table->timestamps();

            // Indexes
            $table->index(['owner_type', 'owner_id'], 'access_token_groups_owner_idx');
        });

        // Create access_tokens table
        Schema::create($tableNames['access_tokens'], function (Blueprint $table) use ($primaryKeyType, $morphType, $tableNames, $useJsonb): void {
            // Primary key
            $this->addPrimaryKey($table, $primaryKeyType);

            // Polymorphic owner (who created/owns the token)
            $this->addMorphColumns($table, 'owner', $morphType);

            // Polymorphic context (what entity the token acts on behalf of) - nullable
            $this->addNullableMorphColumns($table, 'context', $morphType);

            // Polymorphic boundary (tenant/workspace isolation) - nullable
            $this->addNullableMorphColumns($table, 'boundary', $morphType);

            // Group foreign key (nullable)
            $this->addForeignKey($table, 'group_id', $tableNames['access_token_groups'], $primaryKeyType, nullable: true);

            // Token identification
            $table->string('type', 32)->comment('Token type: sk, pk, rk, custom');
            $table->string('environment', 32)->comment('Environment: test, live');
            $table->string('name');
            $table->string('token', 64)->unique();
            $table->string('prefix', 32)->index()->comment('Token prefix: sk_test_, pk_live_, etc.');

            // Permissions & config
            $useJsonb
                ? $table->jsonb('abilities')->nullable()
                : $table->json('abilities')->nullable();
            $useJsonb
                ? $table->jsonb('metadata')->nullable()
                : $table->json('metadata')->nullable();
            $useJsonb
                ? $table->jsonb('derived_metadata')->nullable()
                : $table->json('derived_metadata')->nullable();
            $useJsonb
                ? $table->jsonb('allowed_ips')->nullable()
                : $table->json('allowed_ips')->nullable();
            $useJsonb
                ? $table->jsonb('allowed_domains')->nullable()
                : $table->json('allowed_domains')->nullable();
            $table->unsignedInteger('rate_limit_per_minute')->nullable();

            // Timestamps
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable()->index();
            $table->timestamp('revoked_at')->nullable()->index();
            $table->timestamps();

            // Indexes for common query patterns
            $table->index(['type', 'environment'], 'access_tokens_type_env_idx');
            $table->index(['owner_type', 'owner_id'], 'access_tokens_owner_idx');
            $table->index(['context_type', 'context_id'], 'access_tokens_context_idx');
            $table->index(['boundary_type', 'boundary_id'], 'access_tokens_boundary_idx');
            $table->index('prefix', 'access_tokens_prefix_idx');
        });

        // Create access_token_audit_logs table
        Schema::create($tableNames['access_token_audit_logs'], function (Blueprint $table) use ($primaryKeyType, $tableNames, $useJsonb): void {
            $this->addPrimaryKey($table, $primaryKeyType);

            // Foreign key to token
            $this->addForeignKey($table, 'token_id', $tableNames['access_tokens'], $primaryKeyType);

            $table->string('event', 32)->comment('Event type: created, authenticated, revoked, etc.');
            $table->string('ip_address', 45)->nullable()->comment('Client IP address (IPv6 support)');
            $table->text('user_agent')->nullable();
            $useJsonb
                ? $table->jsonb('metadata')->nullable()
                : $table->json('metadata')->nullable();
            $table->timestamp('created_at');

            // Indexes for common query patterns
            $table->index(['token_id', 'event'], 'access_token_audit_logs_token_event_idx');
            $table->index('created_at', 'access_token_audit_logs_created_idx');
        });
    }

    /**
     * Reverse the migrations by dropping all token management tables.
     *
     * Drops tables in reverse order to avoid foreign key constraint issues.
     * This removes all tokens, groups, and audit log data.
     */
    public function down(): void
    {
        $tableNames = config('bearer.table_names', [
            'access_tokens' => 'access_tokens',
            'access_token_groups' => 'access_token_groups',
            'access_token_audit_logs' => 'access_token_audit_logs',
        ]);

        Schema::dropIfExists($tableNames['access_token_audit_logs']);
        Schema::dropIfExists($tableNames['access_tokens']);
        Schema::dropIfExists($tableNames['access_token_groups']);
    }

    /**
     * Add a primary key column to the table based on the configured type.
     *
     * @param Blueprint       $table The table blueprint
     * @param PrimaryKeyType  $type  The primary key type to use
     */
    private function addPrimaryKey(Blueprint $table, PrimaryKeyType $type): void
    {
        match ($type) {
            PrimaryKeyType::ULID => $table->ulid('id')->primary(),
            PrimaryKeyType::UUID => $table->uuid('id')->primary(),
            PrimaryKeyType::Id => $table->id(),
        };
    }

    /**
     * Add polymorphic morph columns to the table based on the configured type.
     *
     * @param Blueprint $table The table blueprint
     * @param string    $name  The morph column name prefix (e.g., 'owner')
     * @param MorphType $type  The morph type to use
     */
    private function addMorphColumns(Blueprint $table, string $name, MorphType $type): void
    {
        match ($type) {
            MorphType::ULID => $table->ulidMorphs($name),
            MorphType::UUID => $table->uuidMorphs($name),
            MorphType::Numeric => $table->numericMorphs($name),
            MorphType::String => $table->morphs($name),
        };
    }

    /**
     * Add nullable polymorphic morph columns to the table based on the configured type.
     *
     * @param Blueprint $table The table blueprint
     * @param string    $name  The morph column name prefix (e.g., 'context', 'boundary')
     * @param MorphType $type  The morph type to use
     */
    private function addNullableMorphColumns(Blueprint $table, string $name, MorphType $type): void
    {
        match ($type) {
            MorphType::ULID => $table->nullableUlidMorphs($name),
            MorphType::UUID => $table->nullableUuidMorphs($name),
            MorphType::Numeric => $table->nullableNumericMorphs($name),
            MorphType::String => $table->nullableMorphs($name),
        };
    }

    /**
     * Add a foreign key column to the table based on the configured primary key type.
     *
     * @param Blueprint       $table           The table blueprint
     * @param string          $column          The column name for the foreign key
     * @param string          $referencedTable The table being referenced
     * @param PrimaryKeyType  $type            The primary key type to use
     * @param bool            $nullable        Whether the foreign key is nullable
     */
    private function addForeignKey(Blueprint $table, string $column, string $referencedTable, PrimaryKeyType $type, bool $nullable = false): void
    {
        $foreignKey = match ($type) {
            PrimaryKeyType::ULID => $nullable ? $table->foreignUlid($column)->nullable() : $table->foreignUlid($column),
            PrimaryKeyType::UUID => $nullable ? $table->foreignUuid($column)->nullable() : $table->foreignUuid($column),
            PrimaryKeyType::Id => $nullable ? $table->foreignId($column)->nullable() : $table->foreignId($column),
        };

        $foreignKey->constrained($referencedTable)->cascadeOnDelete();
    }
};
