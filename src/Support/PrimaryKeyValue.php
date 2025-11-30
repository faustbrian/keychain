<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Support;

use Cline\Bearer\Enums\PrimaryKeyType;

/**
 * Value object representing a primary key configuration and value.
 *
 * Encapsulates the primary key type and its generated value, providing
 * convenience methods to determine key behavior and requirements. This allows
 * the application to adapt to different primary key strategies seamlessly.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class PrimaryKeyValue
{
    /**
     * Create a new primary key value instance.
     *
     * @param PrimaryKeyType $type  The type of primary key (ID, ULID, or UUID)
     * @param null|string    $value The generated key value (null for auto-incrementing IDs,
     *                              string value for ULID/UUID). For auto-incrementing keys,
     *                              the database will generate the value automatically.
     */
    public function __construct(
        public PrimaryKeyType $type,
        public ?string $value,
    ) {}

    /**
     * Check if this primary key uses database auto-incrementing.
     *
     * Returns true for integer ID types where the database generates the key
     * value automatically, false for ULID/UUID types that require explicit values.
     *
     * @return bool True if the key auto-increments, false otherwise
     */
    public function isAutoIncrementing(): bool
    {
        return $this->type === PrimaryKeyType::Id;
    }

    /**
     * Check if this primary key requires an explicit value.
     *
     * Returns true for ULID and UUID types that need a generated value before
     * insertion, false for auto-incrementing IDs where the database handles
     * value generation.
     *
     * @return bool True if a value must be provided, false for auto-increment
     */
    public function requiresValue(): bool
    {
        return $this->type !== PrimaryKeyType::Id;
    }
}
