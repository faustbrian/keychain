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
 * Exception thrown when a required token ability is missing.
 *
 * Abilities define granular permissions that tokens can possess. This exception
 * occurs when code attempts to perform an action that requires specific abilities
 * that the current token does not have.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class MissingAbilityException extends RuntimeException
{
    /**
     * Create an exception for a single missing ability.
     *
     * This occurs when an action requires a specific ability and the
     * token does not have that ability in its abilities list.
     *
     * @param  string $ability The required ability that is missing
     * @return self   Exception instance with descriptive error message
     */
    public static function missing(string $ability): self
    {
        return new self('Token is missing required ability: '.$ability);
    }

    /**
     * Create an exception for missing any of several abilities.
     *
     * This occurs when an action requires at least one of several abilities,
     * but the token does not have any of them in its abilities list.
     *
     * @param  array<string> $abilities The list of abilities, any of which would satisfy the requirement
     * @return self          Exception instance with descriptive error message
     */
    public static function missingAny(array $abilities): self
    {
        $abilitiesList = implode(', ', $abilities);

        return new self('Token is missing any of the required abilities: '.$abilitiesList);
    }
}
