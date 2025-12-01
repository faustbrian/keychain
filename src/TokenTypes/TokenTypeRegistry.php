<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenTypes;

use Cline\Bearer\Contracts\TokenType;
use Cline\Bearer\Exceptions\InvalidTokenTypeException;

use function array_key_exists;

/**
 * Registry for managing available token types.
 *
 * Provides a central repository for registering, retrieving, and discovering
 * token types within the application. Token types can be registered at
 * application bootstrap and then referenced by name when creating tokens.
 *
 * The registry supports both lookup by exact name and discovery by token
 * prefix, enabling automatic type detection from token strings.
 *
 * Example usage:
 * ```php
 * $registry = new TokenTypeRegistry();
 * $registry->register('secret', new SecretTokenType());
 * $registry->register('publishable', new PublishableTokenType());
 *
 * // Retrieve by name
 * $type = $registry->get('secret');
 *
 * // Find by prefix
 * $type = $registry->findByPrefix('sk'); // Returns SecretTokenType
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenTypeRegistry
{
    /**
     * Registered token types indexed by their name.
     *
     * @var array<string, TokenType>
     */
    private array $types = [];

    /**
     * Register a token type in the registry.
     *
     * Associates a token type instance with a unique key for later retrieval.
     * If a type with the same key already exists, it will be replaced.
     *
     * @param string    $key  Unique identifier for this token type
     * @param TokenType $type Token type instance to register
     */
    public function register(string $key, TokenType $type): void
    {
        $this->types[$key] = $type;
    }

    /**
     * Retrieve a registered token type by its key.
     *
     * @param string $key Token type identifier
     *
     * @throws InvalidTokenTypeException If no token type is registered with the given key
     *
     * @return TokenType The registered token type
     */
    public function get(string $key): TokenType
    {
        if (!$this->has($key)) {
            throw InvalidTokenTypeException::notRegistered($key);
        }

        return $this->types[$key];
    }

    /**
     * Check if a token type is registered.
     *
     * @param  string $key Token type identifier
     * @return bool   True if the type is registered, false otherwise
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->types);
    }

    /**
     * Get all registered token types.
     *
     * @return array<string, TokenType> All registered token types indexed by key
     */
    public function all(): array
    {
        return $this->types;
    }

    /**
     * Find a token type by its prefix.
     *
     * Searches through all registered token types to find one with a matching
     * prefix. This is useful for automatically determining token type from
     * a token string (e.g., 'sk_abc123' -> SecretTokenType).
     *
     * @param  string         $prefix Token prefix to search for
     * @return null|TokenType The matching token type, or null if none found
     */
    public function findByPrefix(string $prefix): ?TokenType
    {
        foreach ($this->types as $type) {
            if ($type->prefix() === $prefix) {
                return $type;
            }
        }

        return null;
    }
}
