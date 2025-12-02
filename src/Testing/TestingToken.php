<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Testing;

use Cline\Bearer\Contracts\HasAbilities;

use function in_array;

/**
 * A configurable in-memory token for testing purposes.
 *
 * Unlike TransientToken which grants all abilities, TestingToken can be
 * configured with specific abilities and a token type, enabling accurate
 * testing of authorization logic without requiring database interaction.
 *
 * This is particularly useful for unit tests where you need to verify that
 * ability checks work correctly for different permission combinations and
 * token types.
 *
 * ```php
 * // Create a token with specific abilities
 * $token = new TestingToken(['read:users', 'write:posts'], 'sk');
 *
 * // Test ability checks
 * $token->can('read:users');  // true
 * $token->cant('delete:all'); // true
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TestingToken implements HasAbilities
{
    /**
     * Create a new testing token instance.
     *
     * @param array<string> $abilities Array of ability strings this token possesses.
     *                                 Use ['*'] for a wildcard token that grants all abilities.
     *                                 Defaults to ['*'] for maximum flexibility in testing.
     * @param null|string   $type      The token type identifier (e.g., 'sk', 'pk', 'rk').
     *                                 Used to test type-specific authorization logic. Null indicates
     *                                 no specific type is set.
     */
    public function __construct(
        private array $abilities = ['*'],
        private ?string $type = null,
    ) {}

    /**
     * Dynamically access token properties.
     *
     * Provides magic property access for the token type. This allows tests to
     * access $token->type just like a real token model would expose it.
     *
     * @param  string $key The property name to access
     * @return mixed  The token type if key is 'type', null otherwise
     */
    public function __get(string $key): mixed
    {
        if ($key === 'type') {
            return $this->type;
        }

        return null;
    }

    /**
     * Determine if the token has a given ability.
     *
     * Returns true if the token either has a wildcard ability ('*') or if the
     * specific ability exists in the abilities array. Uses strict comparison
     * for security.
     *
     * @param  string $ability The ability to check (e.g., 'read:users', 'write:posts')
     * @return bool   True if the token has the ability or wildcard permissions
     */
    public function can(string $ability): bool
    {
        if (in_array('*', $this->abilities, true)) {
            return true;
        }

        return in_array($ability, $this->abilities, true);
    }

    /**
     * Determine if the token is missing a given ability.
     *
     * Returns the inverse of can(). Useful for testing negative authorization
     * cases and ensuring restricted tokens cannot perform certain actions.
     *
     * @param  string $ability The ability to check
     * @return bool   True if the token lacks the ability
     */
    public function cant(string $ability): bool
    {
        return !$this->can($ability);
    }
}
