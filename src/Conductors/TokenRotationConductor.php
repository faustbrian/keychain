<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Conductors;

use Cline\Bearer\BearerManager;
use Cline\Bearer\Contracts\HasApiTokens;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Enums\RotationMode;
use Cline\Bearer\Exceptions\MissingTokenableException;
use Cline\Bearer\NewAccessToken;

use function array_merge;
use function now;

/**
 * Fluent conductor for token rotation with chainable configuration.
 *
 * Provides a builder pattern for rotating personal access tokens with optional
 * rotation modes and grace periods. Supports immediate invalidation, grace period
 * rotation, and dual-valid rotation strategies.
 *
 * Example usage:
 * ```php
 * // Simple rotation (immediate invalidation)
 * $newToken = Bearer::rotate($token)->immediate()->rotate();
 *
 * // Rotation with grace period
 * $newToken = Bearer::rotate($token)
 *     ->withGracePeriod(60)
 *     ->rotate();
 *
 * // With specific mode
 * $newToken = Bearer::rotate($token)
 *     ->using(RotationMode::GracePeriod)
 *     ->rotate();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenRotationConductor
{
    /**
     * Create a new token rotation conductor instance.
     *
     * @param BearerManager $manager     core bearer manager instance providing access
     *                                   to token generation, hashing, type resolution,
     *                                   and audit logging for rotation operations
     * @param AccessToken   $token       The token to be rotated. A new token will be
     *                                   created with identical configuration, while this
     *                                   token's validity is managed per rotation mode.
     * @param RotationMode  $mode        Rotation strategy controlling old token validity.
     *                                   Immediate invalidates old token immediately,
     *                                   GracePeriod keeps it valid temporarily, DualValid
     *                                   maintains both tokens until explicit revocation.
     * @param null|int      $gracePeriod Duration in minutes for which the old token remains
     *                                   valid when using GracePeriod mode. Defaults to 30
     *                                   minutes if not specified. Ignored for other modes.
     */
    public function __construct(
        private BearerManager $manager,
        private AccessToken $token,
        private RotationMode $mode = RotationMode::Immediate,
        private ?int $gracePeriod = null,
    ) {}

    /**
     * Rotate the token with configured settings.
     *
     * Creates a new token with the same configuration as the old token,
     * then handles the old token based on the rotation mode:
     * - Immediate: Old token is invalid immediately
     * - GracePeriod: Old token remains valid for the grace period
     * - DualValid: Both tokens remain valid until explicit revocation
     *
     * ```php
     * // Immediate rotation
     * $newToken = Bearer::rotate($token)->immediate()->rotate();
     *
     * // Grace period rotation
     * $newToken = Bearer::rotate($token)
     *     ->withGracePeriod(30)
     *     ->rotate();
     * ```
     *
     * @return NewAccessToken The newly created token with plain-text value
     */
    public function rotate(): NewAccessToken
    {
        // Create the new token with same configuration
        $tokenType = $this->manager->tokenType($this->token->type);
        $generator = $this->manager->tokenGenerator();
        $hasher = $this->manager->tokenHasher();

        $plainTextToken = $generator->generate($tokenType->prefix(), $this->token->environment);

        $tokenable = $this->token->tokenable;

        if ($tokenable === null || !$tokenable instanceof HasApiTokens) {
            throw MissingTokenableException::forRotation();
        }

        /** @var AccessToken $createdToken */
        $createdToken = $tokenable->tokens()->create([
            'group_id' => $this->token->group_id,
            'type' => $this->token->type,
            'environment' => $this->token->environment,
            'name' => $this->token->name,
            'token' => $hasher->hash($plainTextToken),
            'prefix' => $tokenType->prefix(),
            'abilities' => $this->token->abilities,
            'metadata' => array_merge(
                $this->token->metadata ?? [],
                [
                    'rotated_from' => $this->token->id,
                    'rotation_mode' => $this->mode->value,
                ],
            ),
            'allowed_ips' => $this->token->allowed_ips,
            'allowed_domains' => $this->token->allowed_domains,
            'rate_limit_per_minute' => $this->token->rate_limit_per_minute,
            'expires_at' => $this->token->expires_at,
        ]);

        // Handle the old token based on rotation mode
        match ($this->mode) {
            RotationMode::Immediate => $this->handleImmediate(),
            RotationMode::GracePeriod => $this->handleGracePeriod(),
            RotationMode::DualValid => $this->handleDualValid(),
        };

        $this->manager->auditDriver()->log($this->token, AuditEvent::Rotated, [
            'mode' => $this->mode->value,
            'grace_period' => $this->gracePeriod,
            'new_token_id' => $createdToken->id,
        ]);

        return new NewAccessToken($createdToken, $plainTextToken);
    }

    /**
     * Set the rotation mode.
     *
     * @param  RotationMode $mode Rotation mode to use
     * @return self         New conductor instance with mode configured
     */
    public function using(RotationMode $mode): self
    {
        return new self(
            $this->manager,
            $this->token,
            $mode,
            $this->gracePeriod,
        );
    }

    /**
     * Set the grace period in minutes.
     *
     * During the grace period, both the old and new tokens remain valid.
     * Automatically sets the rotation mode to GracePeriod.
     *
     * @param  int  $minutes Grace period duration in minutes
     * @return self New conductor instance with grace period configured
     */
    public function withGracePeriod(int $minutes): self
    {
        return new self(
            $this->manager,
            $this->token,
            RotationMode::GracePeriod,
            $minutes,
        );
    }

    /**
     * Use immediate rotation mode.
     *
     * Shorthand for using(RotationMode::Immediate). The old token
     * becomes invalid immediately when the new token is created.
     *
     * @return self New conductor instance with immediate mode configured
     */
    public function immediate(): self
    {
        return $this->using(RotationMode::Immediate);
    }

    /**
     * Handle immediate rotation mode.
     *
     * Revokes the old token immediately.
     */
    private function handleImmediate(): void
    {
        $this->token->update(['revoked_at' => now()]);
    }

    /**
     * Handle grace period rotation mode.
     *
     * Sets the old token to expire after the grace period.
     */
    private function handleGracePeriod(): void
    {
        $expiresAt = now()->addMinutes($this->gracePeriod ?? 30);

        $this->token->update([
            'expires_at' => $expiresAt,
            'metadata' => array_merge(
                $this->token->metadata ?? [],
                [
                    'grace_period_expires_at' => $expiresAt->toIso8601String(),
                ],
            ),
        ]);
    }

    /**
     * Handle dual-valid rotation mode.
     *
     * Both tokens remain valid until explicitly revoked.
     * No changes to the old token.
     */
    private function handleDualValid(): void
    {
        // Mark the old token as rotated but keep it valid
        $this->token->update([
            'metadata' => array_merge(
                $this->token->metadata ?? [],
                [
                    'rotated' => true,
                    'rotated_at' => now()->toIso8601String(),
                ],
            ),
        ]);
    }
}
