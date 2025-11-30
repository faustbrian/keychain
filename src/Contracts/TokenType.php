<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

/**
 * Contract for defining token type characteristics and behavior.
 *
 * Token types provide a powerful way to define different classes of tokens with
 * distinct properties, permissions, and constraints. This enables sophisticated
 * token management strategies that go beyond simple authentication.
 *
 * Common token type use cases:
 * - User tokens: Full access, long-lived, rotatable
 * - Service tokens: Specific abilities, server-side only, no expiration
 * - Temporary tokens: Limited scope, short expiration, one-time use
 * - Read-only tokens: Safe for client-side, limited abilities
 * - Admin tokens: Elevated permissions, strict environment controls
 *
 * ```php
 * class ServiceTokenType implements TokenType
 * {
 *     public function name(): string { return 'service'; }
 *     public function prefix(): string { return 'svc'; }
 *     public function defaultAbilities(): array { return ['api:read', 'webhooks:write']; }
 *     public function defaultExpiration(): ?int { return null; } // No expiration
 *     public function defaultRateLimit(): ?int { return 1000; }
 *     public function allowedEnvironments(): array { return ['production']; }
 *     public function isServerSideOnly(): bool { return true; }
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface TokenType
{
    /**
     * Get the unique name/identifier for this token type.
     *
     * The name is used to identify the type when creating tokens and in
     * configuration. Should be lowercase, alphanumeric with hyphens/underscores.
     *
     * @return string Token type name (e.g., 'user', 'service', 'temporary', 'read-only')
     */
    public function name(): string;

    /**
     * Get the prefix used in generated tokens.
     *
     * Token prefixes enable quick visual identification and programmatic type
     * detection. Prefixes appear at the start of the token string, separated
     * by an underscore (e.g., 'usr_abc123', 'svc_xyz789').
     *
     * Best practices:
     * - Keep prefixes short (2-4 characters)
     * - Use only lowercase letters
     * - Make them distinct and memorable
     *
     * @return string Token prefix (e.g., 'usr', 'svc', 'tmp', 'api')
     */
    public function prefix(): string;

    /**
     * Get the default abilities/permissions for this token type.
     *
     * When creating tokens of this type without explicitly specifying abilities,
     * these default abilities are assigned. This ensures consistent permission
     * baselines for each token type.
     *
     * Return an empty array to require explicit ability assignment, or use
     * ['*'] to grant all abilities by default.
     *
     * @return array<int, string> Default ability names (e.g., ['api:read', 'api:write'], ['*'], [])
     */
    public function defaultAbilities(): array;

    /**
     * Get the default expiration time for this token type.
     *
     * Specifies how many minutes from creation until tokens of this type
     * automatically expire. Return null for tokens that never expire.
     *
     * Short-lived tokens (e.g., temporary access) might use 60 (1 hour),
     * while long-lived tokens might use 525600 (1 year) or null.
     *
     * @return null|int Expiration in minutes from creation, or null for no expiration
     */
    public function defaultExpiration(): ?int;

    /**
     * Get the default rate limit for this token type.
     *
     * Specifies the maximum number of requests per minute allowed for tokens
     * of this type. Return null to disable rate limiting for this token type.
     *
     * Rate limits help prevent abuse and manage resource consumption. Service
     * tokens might have high limits (1000+), while public tokens might be
     * heavily restricted (60).
     *
     * @return null|int Requests per minute, or null for no rate limit
     */
    public function defaultRateLimit(): ?int;

    /**
     * Get the environments where this token type can be used.
     *
     * Restricts token usage to specific environments, preventing accidental
     * use of production tokens in development or vice versa. Return an empty
     * array to allow usage in all environments.
     *
     * Environment names should match your application's environment configuration
     * (e.g., APP_ENV values).
     *
     * @return array<int, string> Allowed environment names (e.g., ['production'], ['local', 'staging'], [])
     */
    public function allowedEnvironments(): array;

    /**
     * Determine if this token type must only be used server-side.
     *
     * Server-side-only tokens should never be exposed to clients (browsers,
     * mobile apps) and are intended exclusively for backend-to-backend
     * communication. This helps prevent token leakage in client-side code.
     *
     * The application should enforce this by refusing to return server-side
     * tokens in API responses or including warnings in token creation flows.
     *
     * @return bool True if token must stay server-side, false if client usage is allowed
     */
    public function isServerSideOnly(): bool;
}
