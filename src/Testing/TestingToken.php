<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Testing;

use Cline\Keychain\Contracts\HasAbilities;

use function in_array;

/**
 * A configurable in-memory token for testing purposes.
 *
 * Unlike TransientToken which grants all abilities, TestingToken can be
 * configured with specific abilities and a token type, enabling accurate
 * testing of authorization logic.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TestingToken implements HasAbilities
{
    /**
     * @param array<string> $abilities The abilities this token has
     * @param null|string   $type      The token type (sk, pk, rk, etc.)
     */
    public function __construct(
        private array $abilities = ['*'],
        private ?string $type = null,
    ) {}

    /**
     * Get an attribute from the token.
     *
     * @return null|mixed
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
     */
    public function cant(string $ability): bool
    {
        return !$this->can($ability);
    }
}
