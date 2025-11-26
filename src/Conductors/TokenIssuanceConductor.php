<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Conductors;

use Cline\Keychain\Contracts\HasApiTokens as HasApiTokensContract;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Database\Models\TokenGroup;
use Cline\Keychain\Enums\AuditEvent;
use Cline\Keychain\Exceptions\TokenGroupRefreshException;
use Cline\Keychain\KeychainManager;
use Cline\Keychain\NewAccessToken;
use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;

use function assert;
use function config;
use function is_string;
use function now;

/**
 * Fluent conductor for token issuance with chainable configuration.
 *
 * Provides a builder pattern for creating personal access tokens with optional
 * configuration before final issuance. Supports setting abilities, environments,
 * IP restrictions, domain restrictions, rate limits, and expiration.
 *
 * Example usage:
 * ```php
 * // Simple token issuance
 * $token = Keychain::for($user)->issue('sk', 'My Secret Key');
 *
 * // Token with full configuration
 * $token = Keychain::for($user)
 *     ->abilities(['users:read', 'posts:write'])
 *     ->environment('production')
 *     ->allowedIps(['192.168.1.1'])
 *     ->rateLimit(100)
 *     ->expiresIn(60)
 *     ->issue('sk', 'API Key');
 *
 * // Issue a group of related tokens
 * $group = Keychain::for($user)->issueGroup(
 *     ['sk', 'pk', 'rk'],
 *     'Payment Keys'
 * );
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenIssuanceConductor
{
    /**
     * Create a new token issuance conductor instance.
     *
     * @param KeychainManager            $manager            Core keychain manager instance
     * @param HasApiTokensContract&Model $tokenable          Model that will own the token(s)
     * @param array<int, string>         $abilities          Default abilities for issued tokens
     * @param null|string                $environment        Default environment for issued tokens
     * @param null|array<int, string>    $allowedIps         Default allowed IP addresses
     * @param null|array<int, string>    $allowedDomains     Default allowed domains
     * @param null|int                   $rateLimitPerMinute Default rate limit
     * @param null|DateTimeInterface     $expiresAt          Default expiration timestamp
     * @param array<string, mixed>       $metadata           Default metadata
     */
    public function __construct(
        private KeychainManager $manager,
        private Model&HasApiTokensContract $tokenable,
        private array $abilities = [],
        private ?string $environment = null,
        private ?array $allowedIps = null,
        private ?array $allowedDomains = null,
        private ?int $rateLimitPerMinute = null,
        private ?DateTimeInterface $expiresAt = null,
        private array $metadata = [],
    ) {}

    /**
     * Issue a single token.
     *
     * Creates and persists a new personal access token with the configured
     * settings. Returns a NewAccessToken containing both the database model
     * and the plain-text token (only available once).
     *
     * ```php
     * $token = Keychain::for($user)->issue('sk', 'My Secret Key');
     *
     * // With overrides
     * $token = Keychain::for($user)
     *     ->abilities(['users:read'])
     *     ->issue('sk', 'Read Only Key', ['posts:read']);
     * ```
     *
     * @param  string                  $type               Token type (e.g., 'sk', 'pk', 'rk')
     * @param  string                  $name               Human-readable token name
     * @param  array<int, string>      $abilities          Override default abilities
     * @param  null|string             $environment        Override default environment
     * @param  null|DateTimeInterface  $expiresAt          Override default expiration
     * @param  array<string, mixed>    $metadata           Override default metadata
     * @param  null|array<int, string> $allowedIps         Override default allowed IPs
     * @param  null|array<int, string> $allowedDomains     Override default allowed domains
     * @param  null|int                $rateLimitPerMinute Override default rate limit
     * @return NewAccessToken          Container with persisted token and plain-text value
     */
    public function issue(
        string $type,
        string $name,
        array $abilities = [],
        ?string $environment = null,
        ?DateTimeInterface $expiresAt = null,
        array $metadata = [],
        ?array $allowedIps = null,
        ?array $allowedDomains = null,
        ?int $rateLimitPerMinute = null,
    ): NewAccessToken {
        $tokenType = $this->manager->tokenType($type);
        $generator = $this->manager->tokenGenerator();
        $hasher = $this->manager->tokenHasher();
        $env = $environment ?? $this->environment ?? config('keychain.environments.default', 'test');
        assert(is_string($env));

        $plainTextToken = $generator->generate($tokenType->prefix(), $env);

        /** @var PersonalAccessToken $token */
        $token = $this->tokenable->tokens()->create([
            'type' => $type,
            'environment' => $env,
            'name' => $name,
            'token' => $hasher->hash($plainTextToken),
            'prefix' => $tokenType->prefix(),
            'abilities' => $abilities === [] ? $this->abilities : $abilities,
            'metadata' => $metadata === [] ? $this->metadata : $metadata,
            'allowed_ips' => $allowedIps ?? $this->allowedIps,
            'allowed_domains' => $allowedDomains ?? $this->allowedDomains,
            'rate_limit_per_minute' => $rateLimitPerMinute ?? $this->rateLimitPerMinute,
            'expires_at' => $expiresAt ?? $this->expiresAt,
        ]);

        $this->manager->auditDriver()->log($token, AuditEvent::Created);

        return new NewAccessToken($token, $plainTextToken);
    }

    /**
     * Issue a group of related tokens.
     *
     * Creates a token group containing multiple tokens of different types,
     * all sharing the same name, abilities, and configuration. Useful for
     * creating coordinated token sets like secret/publishable key pairs.
     *
     * ```php
     * $group = Keychain::for($user)->issueGroup(
     *     ['sk', 'pk', 'rk'],
     *     'API Keys'
     * );
     *
     * $secretKey = $group->secretKey();
     * $publishableKey = $group->publishableKey();
     * ```
     *
     * @param  array<int, string>   $types       Token types to create in the group
     * @param  string               $name        Shared name for all tokens
     * @param  array<int, string>   $abilities   Override default abilities
     * @param  null|string          $environment Override default environment
     * @param  array<string, mixed> $metadata    Override default metadata
     * @return TokenGroup           The created group with all tokens
     */
    public function issueGroup(
        array $types,
        string $name,
        array $abilities = [],
        ?string $environment = null,
        array $metadata = [],
    ): TokenGroup {
        /** @var TokenGroup $group */
        $group = $this->tokenable->tokenGroups()->create([
            'name' => $name,
            'metadata' => $metadata === [] ? $this->metadata : $metadata,
        ]);

        $hasher = $this->manager->tokenHasher();

        foreach ($types as $type) {
            $tokenType = $this->manager->tokenType($type);
            $generator = $this->manager->tokenGenerator();
            $env = $environment ?? $this->environment ?? config('keychain.environments.default', 'test');
            assert(is_string($env));

            $plainTextToken = $generator->generate($tokenType->prefix(), $env);

            $this->tokenable->tokens()->create([
                'group_id' => $group->id,
                'type' => $type,
                'environment' => $env,
                'name' => $name,
                'token' => $hasher->hash($plainTextToken),
                'prefix' => $tokenType->prefix(),
                'abilities' => $abilities === [] ? $this->abilities : $abilities,
                'metadata' => $metadata === [] ? $this->metadata : $metadata,
                'allowed_ips' => $this->allowedIps,
                'allowed_domains' => $this->allowedDomains,
                'rate_limit_per_minute' => $this->rateLimitPerMinute,
                'expires_at' => $this->expiresAt,
            ]);
        }

        $freshGroup = $group->fresh();

        if ($freshGroup === null) {
            throw TokenGroupRefreshException::afterCreation();
        }

        return $freshGroup;
    }

    /**
     * Set the environment for issued tokens.
     *
     * @param  string $environment Environment identifier (e.g., 'production', 'development')
     * @return self   New conductor instance with environment configured
     */
    public function environment(string $environment): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $environment,
            $this->allowedIps,
            $this->allowedDomains,
            $this->rateLimitPerMinute,
            $this->expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set default abilities for issued tokens.
     *
     * @param  array<int, string> $abilities Token abilities/permissions
     * @return self               New conductor instance with abilities configured
     */
    public function abilities(array $abilities): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $abilities,
            $this->environment,
            $this->allowedIps,
            $this->allowedDomains,
            $this->rateLimitPerMinute,
            $this->expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set IP restrictions for issued tokens.
     *
     * @param  array<int, string> $ips Allowed IP addresses
     * @return self               New conductor instance with IP restrictions
     */
    public function allowedIps(array $ips): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $this->environment,
            $ips,
            $this->allowedDomains,
            $this->rateLimitPerMinute,
            $this->expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set domain restrictions for issued tokens.
     *
     * @param  array<int, string> $domains Allowed domains
     * @return self               New conductor instance with domain restrictions
     */
    public function allowedDomains(array $domains): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $this->environment,
            $this->allowedIps,
            $domains,
            $this->rateLimitPerMinute,
            $this->expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set rate limit for issued tokens.
     *
     * @param  int  $perMinute Requests per minute limit
     * @return self New conductor instance with rate limit configured
     */
    public function rateLimit(int $perMinute): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $this->environment,
            $this->allowedIps,
            $this->allowedDomains,
            $perMinute,
            $this->expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set expiration timestamp for issued tokens.
     *
     * @param  DateTimeInterface $expiresAt Expiration timestamp
     * @return self              New conductor instance with expiration configured
     */
    public function expiresAt(DateTimeInterface $expiresAt): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $this->environment,
            $this->allowedIps,
            $this->allowedDomains,
            $this->rateLimitPerMinute,
            $expiresAt,
            $this->metadata,
        );
    }

    /**
     * Set expiration in minutes from now.
     *
     * @param  int  $minutes Minutes until expiration
     * @return self New conductor instance with expiration configured
     */
    public function expiresIn(int $minutes): self
    {
        return $this->expiresAt(now()->addMinutes($minutes));
    }

    /**
     * Set metadata for issued tokens.
     *
     * @param  array<string, mixed> $metadata Arbitrary metadata
     * @return self                 New conductor instance with metadata configured
     */
    public function metadata(array $metadata): self
    {
        return new self(
            $this->manager,
            $this->tokenable,
            $this->abilities,
            $this->environment,
            $this->allowedIps,
            $this->allowedDomains,
            $this->rateLimitPerMinute,
            $this->expiresAt,
            $metadata,
        );
    }
}
