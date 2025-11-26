<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Conductors;

use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Enums\AuditEvent;
use Cline\Keychain\Enums\RevocationMode;
use Cline\Keychain\KeychainManager;

use function now;

/**
 * Fluent conductor for token revocation with chainable configuration.
 *
 * Provides a builder pattern for revoking personal access tokens with optional
 * revocation modes and metadata. Supports single token revocation, cascade
 * revocation for entire groups, and partial revocation for specific types.
 *
 * Example usage:
 * ```php
 * // Simple revocation
 * Keychain::revoke($token)->revoke();
 *
 * // Cascade revocation (revoke entire group)
 * Keychain::revoke($token)->cascade()->revoke();
 *
 * // With specific mode
 * Keychain::revoke($token)
 *     ->using(RevocationMode::Cascade)
 *     ->withReason('Security breach detected')
 *     ->revoke();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenRevocationConductor
{
    /**
     * Create a new token revocation conductor instance.
     *
     * @param KeychainManager     $manager Core keychain manager instance
     * @param PersonalAccessToken $token   Token to be revoked
     * @param RevocationMode      $mode    Revocation mode (None, Cascade, Partial, Timed)
     * @param null|string         $reason  Optional revocation reason for audit trail
     */
    public function __construct(
        private KeychainManager $manager,
        private PersonalAccessToken $token,
        private RevocationMode $mode = RevocationMode::None,
        private ?string $reason = null,
    ) {}

    /**
     * Revoke the token with configured settings.
     *
     * Executes the revocation operation based on the configured mode:
     * - None: Revoke only the specified token
     * - Cascade: Revoke all tokens in the same group
     * - Partial: Revoke specific types in the group
     * - Timed: Schedule revocation for later
     *
     * ```php
     * // Basic revocation
     * Keychain::revoke($token)->revoke();
     *
     * // Cascade revocation
     * Keychain::revoke($token)->cascade()->revoke();
     * ```
     */
    public function revoke(): void
    {
        match ($this->mode) {
            RevocationMode::None => $this->revokeSingle(),
            RevocationMode::Cascade => $this->revokeCascade(),
            RevocationMode::Partial => $this->revokePartial(),
            RevocationMode::Timed => $this->revokeTimed(),
        };
    }

    /**
     * Set the revocation mode.
     *
     * @param  RevocationMode $mode Revocation mode to use
     * @return self           New conductor instance with mode configured
     */
    public function using(RevocationMode $mode): self
    {
        return new self(
            $this->manager,
            $this->token,
            $mode,
            $this->reason,
        );
    }

    /**
     * Use cascade mode for revocation.
     *
     * Shorthand for using(RevocationMode::Cascade). Revokes all tokens
     * in the same group as the specified token.
     *
     * @return self New conductor instance with cascade mode configured
     */
    public function cascade(): self
    {
        return $this->using(RevocationMode::Cascade);
    }

    /**
     * Set the revocation reason.
     *
     * Provides additional context for the revocation in the audit trail.
     * Useful for compliance and security analysis.
     *
     * @param  string $reason Reason for revocation
     * @return self   New conductor instance with reason configured
     */
    public function withReason(string $reason): self
    {
        return new self(
            $this->manager,
            $this->token,
            $this->mode,
            $reason,
        );
    }

    /**
     * Revoke only the specified token.
     */
    private function revokeSingle(): void
    {
        $this->token->update(['revoked_at' => now()]);

        $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
            'mode' => 'single',
            'reason' => $this->reason,
        ]);
    }

    /**
     * Revoke all tokens in the same group.
     */
    private function revokeCascade(): void
    {
        if ($this->token->group_id === null) {
            $this->revokeSingle();

            return;
        }

        $group = $this->token->group;

        if ($group === null) {
            $this->revokeSingle();

            return;
        }

        $affectedCount = $group->revokeAll();

        $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
            'mode' => 'cascade',
            'group_id' => $this->token->group_id,
            'affected_count' => $affectedCount,
            'reason' => $this->reason,
        ]);
    }

    /**
     * Revoke specific token types in the group.
     */
    private function revokePartial(): void
    {
        if ($this->token->group_id === null) {
            $this->revokeSingle();

            return;
        }

        // For partial revocation, only revoke tokens of the same type in the group
        $affectedCount = PersonalAccessToken::query()->where('group_id', $this->token->group_id)
            ->where('type', $this->token->type)
            ->update(['revoked_at' => now()]);

        $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
            'mode' => 'partial',
            'group_id' => $this->token->group_id,
            'type' => $this->token->type,
            'affected_count' => $affectedCount,
            'reason' => $this->reason,
        ]);
    }

    /**
     * Schedule revocation for later.
     */
    private function revokeTimed(): void
    {
        // For timed revocation, we would typically dispatch a job
        // For now, just perform immediate revocation
        $this->token->update(['revoked_at' => now()]);

        $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
            'mode' => 'timed',
            'reason' => $this->reason,
        ]);
    }
}
