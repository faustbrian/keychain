<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Keychain\Database\Models\TokenAuditLog;
use Cline\Keychain\Enums\AuditEvent;
use Cline\Keychain\Enums\RevocationMode;
use Cline\Keychain\Facades\Keychain;
use Cline\Keychain\KeychainManager;
use Illuminate\Support\Sleep;

describe('TokenRevocationConductor', function (): void {
    describe('Happy Path', function (): void {
        it('revokes single token using default mode', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            app(KeychainManager::class)->createRevocationConductor($token)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();
            expect($token->fresh()->revoked_at)->not->toBeNull();

            $auditLog = TokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog)->not->toBeNull();
            expect($auditLog->metadata['mode'])->toBe('single');
        });

        it('revokes token using cascade mode shorthand', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())->cascade()->revoke();

            // Assert
            expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->publishableKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())->using(RevocationMode::Cascade)->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            app(KeychainManager::class)->createRevocationConductor($token)->withReason($reason)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['reason'])->toBe($reason);
        });

        it('revokes with cascade mode and reason', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Test Group');
            $reason = 'Account compromised';

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())
                ->cascade()
                ->withReason($reason)
                ->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('cascade');
            expect($auditLog->metadata['reason'])->toBe($reason);
        });

        it('revokes using partial mode for same-type tokens only', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())->using(RevocationMode::Partial)->revoke();

            // Assert
            // Only sk tokens should be revoked (same type)
            expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
            // Other types should NOT be revoked
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeFalse();
            expect($group->fresh()->publishableKey()->isRevoked())->toBeFalse();

            $auditLog = TokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['mode'])->toBe('partial');
            expect($auditLog->metadata['type'])->toBe('sk');
            expect($auditLog->metadata['affected_count'])->toBe(1);
        });

        it('revokes using timed mode', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            app(KeychainManager::class)->createRevocationConductor($token)->using(RevocationMode::Timed)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            $conductor1 = app(KeychainManager::class)->createRevocationConductor($token);
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
            $conductor1 = app(KeychainManager::class)->createRevocationConductor($token);
            $conductor2 = $conductor1->withReason('Test reason');

            // Assert
            expect($conductor1)->not->toBe($conductor2);
        });

        it('chains multiple configuration methods', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())
                ->using(RevocationMode::Cascade)
                ->withReason('Chained test')
                ->revoke();

            // Assert
            expect($group->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            app(KeychainManager::class)->createRevocationConductor($token)->cascade()->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            app(KeychainManager::class)->createRevocationConductor($token)->using(RevocationMode::Partial)->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            $group = Keychain::for($user)->issueGroup(['sk'], 'Test Group');
            $token = $group->secretKey();

            // Manually set group_id without actual group (simulate orphaned token)
            $token->update(['group_id' => 99_999]);

            // Act
            app(KeychainManager::class)->createRevocationConductor($token->fresh())->cascade()->revoke();

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();

            $auditLog = TokenAuditLog::query()
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
            app(KeychainManager::class)->createRevocationConductor($token)
                ->withReason($reason)
                ->using(RevocationMode::None)
                ->revoke();

            // Assert
            $auditLog = TokenAuditLog::query()
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
            app(KeychainManager::class)->createRevocationConductor($token)->revoke();

            // Assert
            $auditLog = TokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['reason'])->toBeNull();
        });

        it('cascades only within same group', function (): void {
            // Arrange
            $user = createUser();
            $group1 = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            $group2 = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group1->secretKey())->cascade()->revoke();

            // Assert
            expect($group1->fresh()->tokens->every->isRevoked())->toBeTrue();
            expect($group2->fresh()->tokens->every->isRevoked())->toBeFalse();
        });

        it('partial mode only affects tokens with same type in group', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');
            $pkToken = $group->publishableKey();

            // Act
            app(KeychainManager::class)->createRevocationConductor($pkToken)->using(RevocationMode::Partial)->revoke();

            // Assert
            // Only pk should be revoked (partial matches same type only)
            expect($group->fresh()->publishableKey()->isRevoked())->toBeTrue();
            expect($group->fresh()->secretKey()->isRevoked())->toBeFalse();
            expect($group->fresh()->restrictedKey()->isRevoked())->toBeFalse();

            $auditLog = TokenAuditLog::query()
                ->where('token_id', $pkToken->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['type'])->toBe('pk');
            expect($auditLog->metadata['affected_count'])->toBe(1);
        });

        it('allows revoking already revoked token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act - First revocation
            app(KeychainManager::class)->createRevocationConductor($token)->revoke();
            $firstRevokedAt = $token->fresh()->revoked_at;

            // Act - Second revocation
            Sleep::sleep(1); // Ensure different timestamp
            app(KeychainManager::class)->createRevocationConductor($token->fresh())->revoke();
            $secondRevokedAt = $token->fresh()->revoked_at;

            // Assert
            expect($token->fresh()->isRevoked())->toBeTrue();
            expect($secondRevokedAt)->not->toBe($firstRevokedAt);

            $auditLogs = TokenAuditLog::query()
                ->where('token_id', $token->id)
                ->where('event', AuditEvent::Revoked)
                ->get();

            expect($auditLogs)->toHaveCount(2);
        });

        it('does not affect other users tokens during cascade', function (): void {
            // Arrange
            $user1 = createUser(['email' => 'user1@example.com']);
            $user2 = createUser(['email' => 'user2@example.com']);
            $group1 = Keychain::for($user1)->issueGroup(['sk', 'pk'], 'User 1 Group');
            $group2 = Keychain::for($user2)->issueGroup(['sk', 'pk'], 'User 2 Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group1->secretKey())->cascade()->revoke();

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
            $conductor = app(KeychainManager::class)->createRevocationConductor($token);

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
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())->cascade()->revoke();

            // Assert
            $auditLog = TokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog->metadata['affected_count'])->toBe(3);
        });

        it('logs affected count correctly for partial', function (): void {
            // Arrange
            $user = createUser();
            $group = Keychain::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Test Group');

            // Act
            app(KeychainManager::class)->createRevocationConductor($group->secretKey())->using(RevocationMode::Partial)->revoke();

            // Assert
            $auditLog = TokenAuditLog::query()
                ->where('token_id', $group->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            // Only sk tokens in the group (just 1 in this case)
            expect($auditLog->metadata['affected_count'])->toBe(1);
        });

        it('cascade shorthand equivalent to using RevocationMode::Cascade', function (): void {
            // Arrange
            $user = createUser();
            $group1 = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            $group2 = Keychain::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

            // Act - Use cascade() shorthand
            app(KeychainManager::class)->createRevocationConductor($group1->secretKey())->cascade()->revoke();

            // Act - Use explicit mode
            app(KeychainManager::class)->createRevocationConductor($group2->secretKey())->using(RevocationMode::Cascade)->revoke();

            // Assert - Both should have same result
            expect($group1->fresh()->tokens->every->isRevoked())->toBeTrue();
            expect($group2->fresh()->tokens->every->isRevoked())->toBeTrue();

            $auditLog1 = TokenAuditLog::query()
                ->where('token_id', $group1->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            $auditLog2 = TokenAuditLog::query()
                ->where('token_id', $group2->secretKey()->id)
                ->where('event', AuditEvent::Revoked)
                ->first();

            expect($auditLog1->metadata['mode'])->toBe('cascade');
            expect($auditLog2->metadata['mode'])->toBe('cascade');
        });
    });
});
