<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Support;

use Cline\Keychain\Enums\PrimaryKeyType;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

/**
 * Generates primary key values based on configuration.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PrimaryKeyGenerator
{
    public static function generate(): PrimaryKeyValue
    {
        /** @var int|string $configValue */
        $configValue = Config::get('keychain.primary_key_type', 'id');
        $primaryKeyType = PrimaryKeyType::tryFrom($configValue) ?? PrimaryKeyType::Id;

        $value = match ($primaryKeyType) {
            PrimaryKeyType::Ulid => Str::lower((string) Str::ulid()),
            PrimaryKeyType::Uuid => Str::lower((string) Str::uuid()),
            PrimaryKeyType::Id => null,
        };

        return new PrimaryKeyValue($primaryKeyType, $value);
    }
}
