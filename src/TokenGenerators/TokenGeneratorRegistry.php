<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenGenerators;

use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Exceptions\TokenGeneratorNotRegisteredException;

use function array_key_exists;
use function array_keys;

/**
 * Registry for managing token generator implementations.
 *
 * Provides a centralized location for registering, retrieving, and managing
 * different token generator strategies. Allows applications to configure which
 * generator to use as the default and switch between implementations as needed.
 *
 * Example usage:
 * ```php
 * $registry = new TokenGeneratorRegistry();
 *
 * // Register generators
 * $registry->register('seam', new SeamTokenGenerator());
 * $registry->register('uuid', new UuidTokenGenerator());
 * $registry->register('random', new RandomTokenGenerator());
 *
 * // Retrieve a specific generator
 * $generator = $registry->get('uuid');
 *
 * // Check if a generator exists
 * if ($registry->has('seam')) {
 *     // ...
 * }
 *
 * // Get the default generator
 * $default = $registry->default();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenGeneratorRegistry
{
    /**
     * Registered token generators.
     *
     * @var array<string, TokenGenerator>
     */
    private array $generators = [];

    /**
     * Name of the default generator.
     */
    private ?string $defaultGenerator = null;

    /**
     * Register a token generator with a given name.
     *
     * @param string         $name      Unique identifier for this generator
     * @param TokenGenerator $generator The generator implementation to register
     */
    public function register(string $name, TokenGenerator $generator): void
    {
        $this->generators[$name] = $generator;

        // Set the first registered generator as default if none is set
        if ($this->defaultGenerator === null) {
            $this->defaultGenerator = $name;
        }
    }

    /**
     * Retrieve a registered token generator by name.
     *
     * @param string $name The name of the generator to retrieve
     *
     * @throws TokenGeneratorNotRegisteredException If the generator is not registered
     *
     * @return TokenGenerator The requested generator instance
     */
    public function get(string $name): TokenGenerator
    {
        if (!$this->has($name)) {
            throw TokenGeneratorNotRegisteredException::forName($name);
        }

        return $this->generators[$name];
    }

    /**
     * Check if a token generator is registered.
     *
     * @param  string $name The name of the generator to check
     * @return bool   True if registered, false otherwise
     */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->generators);
    }

    /**
     * Get the default token generator.
     *
     * @throws TokenGeneratorNotRegisteredException If no generators are registered
     *
     * @return TokenGenerator The default generator instance
     */
    public function default(): TokenGenerator
    {
        if ($this->defaultGenerator === null) {
            throw TokenGeneratorNotRegisteredException::noDefault();
        }

        return $this->get($this->defaultGenerator);
    }

    /**
     * Set the default token generator by name.
     *
     * @param string $name The name of the generator to set as default
     *
     * @throws TokenGeneratorNotRegisteredException If the generator is not registered
     */
    public function setDefault(string $name): void
    {
        if (!$this->has($name)) {
            throw TokenGeneratorNotRegisteredException::cannotSetAsDefault($name);
        }

        $this->defaultGenerator = $name;
    }

    /**
     * Get all registered generator names.
     *
     * @return array<string> List of registered generator names
     */
    public function all(): array
    {
        return array_keys($this->generators);
    }
}
