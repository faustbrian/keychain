<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenHashers;

use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Exceptions\TokenHasherNotRegisteredException;

use function array_key_exists;

/**
 * Registry for managing token hasher implementations.
 *
 * Maintains a collection of token hashers keyed by name, allowing
 * runtime registration and retrieval of hasher implementations.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenHasherRegistry
{
    /**
     * Registered token hashers.
     *
     * @var array<string, TokenHasher>
     */
    private array $hashers = [];

    /**
     * The default hasher name.
     */
    private ?string $defaultHasher = null;

    /**
     * Register a token hasher with the given name.
     *
     * @param string      $name   The hasher name
     * @param TokenHasher $hasher The hasher implementation
     */
    public function register(string $name, TokenHasher $hasher): void
    {
        $this->hashers[$name] = $hasher;
    }

    /**
     * Get a token hasher by name.
     *
     * @param string $name The hasher name
     *
     * @throws TokenHasherNotRegisteredException If the hasher is not registered
     *
     * @return TokenHasher The hasher implementation
     */
    public function get(string $name): TokenHasher
    {
        if (!$this->has($name)) {
            throw TokenHasherNotRegisteredException::forHasher($name);
        }

        return $this->hashers[$name];
    }

    /**
     * Check if a token hasher is registered.
     *
     * @param  string $name The hasher name
     * @return bool   True if the hasher is registered
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->hashers);
    }

    /**
     * Get the default token hasher.
     *
     * @throws TokenHasherNotRegisteredException If no default hasher is set or it's not registered
     *
     * @return TokenHasher The default hasher implementation
     */
    public function default(): TokenHasher
    {
        if ($this->defaultHasher === null) {
            throw TokenHasherNotRegisteredException::noDefault();
        }

        return $this->get($this->defaultHasher);
    }

    /**
     * Set the default token hasher.
     *
     * @param string $name The hasher name to use as default
     */
    public function setDefault(string $name): void
    {
        $this->defaultHasher = $name;
    }

    /**
     * Get all registered token hashers.
     *
     * @return array<string, TokenHasher> The registered hashers
     */
    public function all(): array
    {
        return $this->hashers;
    }
}
