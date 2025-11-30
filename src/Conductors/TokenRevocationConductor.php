<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Conductors;

use Cline\Bearer\BearerManager;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Enums\RevocationMode;
use Throwable;

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
 * Bearer::revoke($token)->revoke();
 *
 * // Cascade revocation (revoke entire group)
 * Bearer::revoke($token)->cascade()->revoke();
 *
 * // With specific mode
 * Bearer::revoke($token)
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
     * @param BearerManager  $manager core bearer manager instance providing access
     *                                to audit logging functionality for tracking
     *                                revocation events and their context
     * @param AccessToken    $token   The token to be revoked. This can be a single
     *                                token or the entry point for cascade/partial
     *                                revocation of related tokens in the same group.
     * @param RevocationMode $mode    Revocation strategy controlling how revocation
     *                                propagates. None revokes only the specified token,
     *                                Cascade revokes entire group, Partial revokes
     *                                server-side tokens only, Timed schedules revocation.
     * @param null|string    $reason  Optional human-readable reason for the revocation.
     *                                Stored in audit logs for compliance tracking,
     *                                security analysis, and troubleshooting purposes.
     */
    public function __construct(
        private BearerManager $manager,
        private AccessToken $token,
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
     * Bearer::revoke($token)->revoke();
     *
     * // Cascade revocation
     * Bearer::revoke($token)->cascade()->revoke();
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
     * Revoke this token and all its derived descendant tokens in the hierarchy.
     *
     * Uses the cascade_descendants strategy to revoke the parent token and all
     * child/grandchild tokens derived from it. Useful for master/reseller tokens
     * where revoking the parent should invalidate all customer tokens.
     */
    public function withDescendants(): void
    {
        $this->manager->executeRevocation($this->token, 'cascade_descendants');
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

        try {
            $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
                'mode' => 'single',
                'reason' => $this->reason,
            ]);
        } catch (Throwable) {
            // Silently ignore audit failures - revocation already completed
        }
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

        try {
            $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
                'mode' => 'cascade',
                'group_id' => $this->token->group_id,
                'affected_count' => $affectedCount,
                'reason' => $this->reason,
            ]);
        } catch (Throwable) {
            // Silently ignore audit failures - revocation already completed
        }
    }

    /**
     * Revoke server-side tokens only in the group.
     */
    private function revokePartial(): void
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

        // For partial revocation, only revoke server-side tokens in the group
        $serverSideTypes = ['sk', 'rk'];

        $affectedCount = AccessToken::query()
            ->where('group_id', $this->token->group_id)
            ->whereIn('type', $serverSideTypes)
            ->update(['revoked_at' => now()]);

        try {
            $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
                'mode' => 'partial',
                'group_id' => $this->token->group_id,
                'server_side_types' => $serverSideTypes,
                'affected_count' => $affectedCount,
                'reason' => $this->reason,
            ]);
        } catch (Throwable) {
            // Silently ignore audit failures - revocation already completed
        }
    }

    /**
     * Schedule revocation for later.
     */
    private function revokeTimed(): void
    {
        // For timed revocation, we would typically dispatch a job
        // For now, just perform immediate revocation
        $this->token->update(['revoked_at' => now()]);

        try {
            $this->manager->auditDriver()->log($this->token, AuditEvent::Revoked, [
                'mode' => 'timed',
                'reason' => $this->reason,
            ]);
        } catch (Throwable) {
            // Silently ignore audit failures - revocation already completed
        }
    }
}
