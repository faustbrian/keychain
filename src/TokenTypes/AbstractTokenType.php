<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\TokenTypes;

use Cline\Keychain\Contracts\TokenType;

/**
 * Base implementation for token types with configurable behavior.
 *
 * Provides a reusable foundation for implementing concrete token types with
 * different characteristics. Subclasses can configure all aspects of token
 * behavior through constructor parameters or override specific methods for
 * custom logic.
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class AbstractTokenType implements TokenType
{
    /**
     * Create a new token type instance.
     *
     * @param string             $name                Token type identifier
     * @param string             $prefix              Token prefix for visual identification
     * @param array<int, string> $defaultAbilities    Default permissions for tokens of this type
     * @param null|int           $defaultExpiration   Expiration in minutes, or null for no expiration
     * @param null|int           $defaultRateLimit    Requests per minute, or null for no limit
     * @param array<int, string> $allowedEnvironments Environments where tokens can be used
     * @param bool               $serverSideOnly      Whether tokens must stay server-side
     */
    public function __construct(
        protected readonly string $name,
        protected readonly string $prefix,
        protected readonly array $defaultAbilities = ['*'],
        protected readonly ?int $defaultExpiration = null,
        protected readonly ?int $defaultRateLimit = null,
        protected readonly array $allowedEnvironments = ['test', 'live'],
        protected readonly bool $serverSideOnly = false,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * {@inheritDoc}
     */
    public function prefix(): string
    {
        return $this->prefix;
    }

    /**
     * {@inheritDoc}
     */
    public function defaultAbilities(): array
    {
        return $this->defaultAbilities;
    }

    /**
     * {@inheritDoc}
     */
    public function defaultExpiration(): ?int
    {
        return $this->defaultExpiration;
    }

    /**
     * {@inheritDoc}
     */
    public function defaultRateLimit(): ?int
    {
        return $this->defaultRateLimit;
    }

    /**
     * {@inheritDoc}
     */
    public function allowedEnvironments(): array
    {
        return $this->allowedEnvironments;
    }

    /**
     * {@inheritDoc}
     */
    public function isServerSideOnly(): bool
    {
        return $this->serverSideOnly;
    }
}
