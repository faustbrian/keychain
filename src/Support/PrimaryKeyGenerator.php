<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Support;

use Cline\Bearer\Enums\PrimaryKeyType;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

/**
 * Generates primary key values based on application configuration.
 *
 * Reads the configured primary key type from the bearer configuration and
 * generates the appropriate value (ULID, UUID, or auto-incrementing ID). This
 * allows the application to use different primary key strategies for token
 * storage without changing the codebase.
 *
 * Supported key types:
 * - ULID: Generates a lowercase ULID string for sortable, distributed IDs
 * - UUID: Generates a lowercase UUID string for globally unique IDs
 * - ID: Returns null, indicating auto-incrementing integer primary keys
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PrimaryKeyGenerator
{
    /**
     * Generate a primary key value based on the configured strategy.
     *
     * Reads the 'bearer.primary_key_type' configuration value and generates
     * the appropriate primary key. For ULID and UUID types, generates a new
     * unique identifier. For ID type, returns null to allow database auto-increment.
     *
     * @return PrimaryKeyValue Value object containing the key type and generated value
     */
    public static function generate(): PrimaryKeyValue
    {
        /** @var int|string $configValue */
        $configValue = Config::get('bearer.primary_key_type', 'id');
        $primaryKeyType = PrimaryKeyType::tryFrom($configValue) ?? PrimaryKeyType::Id;

        $value = match ($primaryKeyType) {
            PrimaryKeyType::ULID => Str::lower((string) Str::ulid()),
            PrimaryKeyType::UUID => Str::lower((string) Str::uuid()),
            PrimaryKeyType::Id => null,
        };

        return new PrimaryKeyValue($primaryKeyType, $value);
    }
}
