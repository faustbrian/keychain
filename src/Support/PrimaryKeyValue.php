<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Support;

use Cline\Keychain\Enums\PrimaryKeyType;

/**
 * Value object representing a primary key configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class PrimaryKeyValue
{
    public function __construct(
        public PrimaryKeyType $type,
        public ?string $value,
    ) {}

    public function isAutoIncrementing(): bool
    {
        return $this->type === PrimaryKeyType::Id;
    }

    public function requiresValue(): bool
    {
        return $this->type !== PrimaryKeyType::Id;
    }
}
