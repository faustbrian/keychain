<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

use function implode;

/**
 * Exception thrown when derived token abilities are not a subset of parent abilities.
 *
 * Token derivation enforces that child tokens cannot have more permissions than
 * their parent tokens. This exception occurs when attempting to create a derived
 * token with abilities that exceed or differ from the parent's abilities.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidDerivedAbilitiesException extends RuntimeException
{
    /**
     * Create an exception for abilities that are not a valid subset.
     *
     * @param  array<int, string> $childAbilities  The abilities requested for the child token
     * @param  array<int, string> $parentAbilities The abilities of the parent token
     * @return self               Exception instance with descriptive error message
     */
    public static function create(array $childAbilities, array $parentAbilities): self
    {
        return new self(
            'Derived token abilities ['.implode(', ', $childAbilities).'] '.
            'must be a subset of parent token abilities ['.implode(', ', $parentAbilities).'].',
        );
    }
}
