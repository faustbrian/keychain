<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\BearerManager;
use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Enums\RevocationMode;
use Cline\Bearer\Facades\Bearer;
use Illuminate\Support\Sleep;

describe('TokenRevocationConductor', function (): void {
    describe('Happy Path', function (): void {
        it('revokes single token using default mode', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            app(BearerManager::class)->revoke($token)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();
            expect($token->fresh()->revoked_at)->not->toBeNull();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog)->not->toBeNull();
            expect($auditLog->metadata['mode'])->toBe('single');
        });

        it('revokes token using cascade mode shorthand', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())->cascade()->revoke();

            // Assert
            expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->publishableKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog)->not->toBeNull();
            expect($auditLog->metadata['mode'])->toBe('cascade');
            expect($auditLog->metadata['group_id'])->toBe($group->id);
            expect($auditLog->metadata['affected_count'])->toBe(3);
        });

        it('revokes token using explicit cascade mode', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())->using(RevocationMode::Cascade)->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('cascade');
        });

        it('revokes token with reason captured in audit log', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $reason = 'Security breach detected';

            // Act
            app(BearerManager::class)->revoke($token)->withReason($reason)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['reason'])->toBe($reason);
        });

        it('revokes with cascade mode and reason', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Test Group');
            $reason = 'Account compromised';

            // Act
            app(BearerManager::class)->revoke($group->secretKey())
                ->cascade()
                ->withReason($reason)
                ->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('cascade');
            expect($auditLog->metadata['reason'])->toBe($reason);
        });

        it('revokes using partial mode for same-type tokens only', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())->using(RevocationMode::Partial)->revoke();

            // Assert
            // Partial revokes server-side tokens (sk + rk)
            expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->publishableKey()->isRevoked())->toBeFalse();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('partial');
            expect($auditLog->metadata['server_side_types'])->toBe(['sk', 'rk']);
            expect($auditLog->metadata['affected_count'])->toBe(2);
        });

        it('revokes using timed mode', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            app(BearerManager::class)->revoke($token)->using(RevocationMode::Timed)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('timed');
        });

        it('returns new instance when using different modes', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $conductor1 = app(BearerManager::class)->revoke($token);
            $conductor2 = $conductor1->cascade();
            $conductor3 = $conductor2->using(RevocationMode::Partial);

            // Assert
            expect($conductor1)->not->toBe($conductor2);
            expect($conductor2)->not->toBe($conductor3);
            expect($conductor1)->not->toBe($conductor3);
        });

        it('returns new instance when setting reason', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $conductor1 = app(BearerManager::class)->revoke($token);
            $conductor2 = $conductor1->withReason('Test reason');

            // Assert
            expect($conductor1)->not->toBe($conductor2);
        });

        it('chains multiple configuration methods', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())
                ->using(RevocationMode::Cascade)
                ->withReason('Chained test')
                ->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('cascade');
            expect($auditLog->metadata['reason'])->toBe('Chained test');
        });
    });

    describe('Sad Path', function (): void {
        it('falls back to single revocation when cascade mode used on ungrouped token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            expect($token->group_id)->toBeNull();

            // Act
            app(BearerManager::class)->revoke($token)->cascade()->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            // Should fall back to single mode
            expect($auditLog->metadata['mode'])->toBe('single');
        });

        it('falls back to single revocation when partial mode used on ungrouped token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            expect($token->group_id)->toBeNull();

            // Act
            app(BearerManager::class)->revoke($token)->using(RevocationMode::Partial)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            // Should fall back to single mode
            expect($auditLog->metadata['mode'])->toBe('single');
        });
    });

    describe('Edge Cases', function (): void {
        it('handles null group relationship gracefully', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk'], 'Test Group');
            $token = $group->secretKey();

            // Manually set group_id without actual group (simulate orphaned token)
            $token->update(['group_id' => 99_999]);

            // Act
            app(BearerManager::class)->revoke($token->fresh())->cascade()->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            // Should fall back to single mode when group is null
            expect($auditLog->metadata['mode'])->toBe('single');
        });

        it('preserves reason through multiple configuration calls', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $reason = 'Original reason';

            // Act
            app(BearerManager::class)->revoke($token)
                ->withReason($reason)
                ->using(RevocationMode::None)
                ->revoke();

            // Assert
            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['reason'])->toBe($reason);
        });

        it('handles empty reason as null', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            app(BearerManager::class)->revoke($token)->revoke();

            // Assert
            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['reason'])->toBeNull();
        });

        it('cascades only within same group', function (): void {
            // Arrange
            $user = createUser();
            $group1 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            $group2 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

            // Act
            app(BearerManager::class)->revoke($group1->secretKey())->cascade()->revoke();

            // Assert
            expect($group1->fresh()->tokens->every->isRevoked())->toBeTrue();
            expect($group2->fresh()->tokens->every->isRevoked())->toBeFalse();
        });

        it('partial mode revokes server-side tokens even when triggered from client-side token', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');
            $pkToken = $group->publishableKey();

            // Act
            app(BearerManager::class)->revoke($pkToken)->using(RevocationMode::Partial)->revoke();

            // Assert
            // Partial always revokes server-side tokens (sk + rk), not pk
            expect($group->fresh()->publishableKey()->isRevoked())->toBeFalse();
            expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeTrue();

            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $pkToken->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['server_side_types'])->toBe(['sk', 'rk']);
            expect($auditLog->metadata['affected_count'])->toBe(2);
        });

        it('allows revoking already revoked token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act - First revocation
            app(BearerManager::class)->revoke($token)->revoke();
            $firstRevokedAt = $token->fresh()->revoked_at;

            // Act - Second revocation
            Sleep::sleep(1); // Ensure different timestamp
            app(BearerManager::class)->revoke($token->fresh())->revoke();
            $secondRevokedAt = $token->fresh()->revoked_at;

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();
            expect($secondRevokedAt)->not->toBe($firstRevokedAt);

            $auditLogs = AccessTokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->get();

            expect($auditLogs)->toHaveCount(2);
        });

        it('does not affect other users tokens during cascade', function (): void {
            // Arrange
            $user1 = createUser(['email' => 'user1@example.com']);
            $user2 = createUser(['email' => 'user2@example.com']);
            $group1 = Bearer::for($user1)->issueGroup(['sk', 'pk'], 'User 1 Group');
            $group2 = Bearer::for($user2)->issueGroup(['sk', 'pk'], 'User 2 Group');

            // Act
            app(BearerManager::class)->revoke($group1->secretKey())->cascade()->revoke();

            // Assert
            expect($group1->fresh()->tokens->every->isRevoked())->toBeTrue();
            expect($group2->fresh()->tokens->every->isRevoked())->toBeFalse();
        });
    });

    describe('Regression', function (): void {
        it('maintains immutability of conductor instances', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $conductor = app(BearerManager::class)->revoke($token);

            // Act
            $withCascade = $conductor->cascade();
            $withReason = $conductor->withReason('Test');
            $withMode = $conductor->using(RevocationMode::Timed);

            // Assert - Original conductor should be unchanged
            expect($conductor)->not->toBe($withCascade);
            expect($conductor)->not->toBe($withReason);
            expect($conductor)->not->toBe($withMode);

            // Each configuration should create new instance
            expect($withCascade)->not->toBe($withReason);
            expect($withCascade)->not->toBe($withMode);
            expect($withReason)->not->toBe($withMode);
        });

        it('logs affected count correctly for cascade', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())->cascade()->revoke();

            // Assert
            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['affected_count'])->toBe(3);
        });

        it('logs affected count correctly for partial', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(BearerManager::class)->revoke($group->secretKey())->using(RevocationMode::Partial)->revoke();

            // Assert
            $auditLog = AccessTokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            // Server-side tokens in the group (sk + rk = 2)
            expect($auditLog->metadata['affected_count'])->toBe(2);
        });

        it('cascade shorthand equivalent to using RevocationMode::Cascade', function (): void {
            // Arrange
            $user = createUser();
            $group1 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            $group2 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

            // Act - Use cascade() shorthand
            app(BearerManager::class)->revoke($group1->secretKey())->cascade()->revoke();

            // Act - Use explicit mode
            app(BearerManager::class)->revoke($group2->secretKey())->using(RevocationMode::Cascade)->revoke();

            // Assert - Both should have same result
            expect($group1->fresh()->tokens->every->isRevoked())->toBeTrue();
            expect($group2->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog1 = AccessTokenAuditLog::query()
                ->where('token_id', $group1->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            $auditLog2 = AccessTokenAuditLog::query()
                ->where('token_id', $group2->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog1->metadata['mode'])->toBe('cascade');
            expect($auditLog2->metadata['mode'])->toBe('cascade');
        });
    });
});
