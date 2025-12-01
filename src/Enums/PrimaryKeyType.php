<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Enums;

/**
 * Defines supported primary key types for models.
 *
 * Used to determine how to generate primary keys for token records when using
 * the database driver. Affects both the migration schema and the ID generation
 * strategy during record creation.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum PrimaryKeyType: string
{
    /**
     * Standard auto-incrementing integer primary key.
     *
     * Uses database auto-increment functionality. No pre-generation needed.
     */
    case Id = 'id';

    /**
     * UUID (Universally Unique Identifier) primary key.
     *
     * 36-character globally unique identifier with cryptographic randomness.
     * Pre-generated for record creation to enable predictable identifiers.
     */
    case UUID = 'uuid';

    /**
     * ULID (Universally Unique Lexicographically Sortable Identifier) primary key.
     *
     * 26-character time-ordered identifier providing sortability and uniqueness.
     * Pre-generated for record creation to enable predictable identifiers.
     */
    case ULID = 'ulid';
}
