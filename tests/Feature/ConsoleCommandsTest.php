<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;

describe('Prune Audit Logs Command', function (): void {
    it('prunes audit logs older than configured retention days', function (): void {
        // Arrange
        $user = createUser();
        $token = createToken($user);

        // Create old audit logs (older than 90 days)
        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(91),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(95),
        ]);

        // Create recent audit logs (within 90 days)
        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(89),
        ]);

        // Act
        $exitCode = Artisan::call('bearer:prune-audit-logs');

        // Assert
        expect($exitCode)->toBe(0);
        // Should have 2 recent logs: the one created in test + the automatic creation log
        expect(AccessTokenAuditLog::query()->where('token_id', $token->id)->count())->toBe(2);
    });

    it('respects --days option override', function (): void {
        // Arrange
        $user = createUser();
        $token = createToken($user);

        // Create audit logs older than 30 days
        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(31),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(45),
        ]);

        // Create audit logs within 30 days
        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(29),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(15),
        ]);

        // Act
        $exitCode = Artisan::call('bearer:prune-audit-logs', ['--days' => 30]);

        // Assert
        expect($exitCode)->toBe(0);
        // Should have 3 recent logs: the two created in test + the automatic creation log
        expect(AccessTokenAuditLog::query()->where('token_id', $token->id)->count())->toBe(3);
    });

    it('returns SUCCESS exit code', function (): void {
        // Arrange
        $user = createUser();
        $token = createToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(100),
        ]);

        // Act
        $exitCode = Artisan::call('bearer:prune-audit-logs');

        // Assert
        expect($exitCode)->toBe(0);
    });

    it('outputs correct info message', function (): void {
        // Arrange
        $user = createUser();
        $token = createToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(91),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(92),
        ]);

        // Act
        Artisan::call('bearer:prune-audit-logs');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 2 audit logs older than 90 days');
    });

    it('handles case when no audit logs need pruning', function (): void {
        // Arrange
        $user = createUser();
        $token = createToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(10),
        ]);

        // Act
        Artisan::call('bearer:prune-audit-logs');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 0 audit logs older than 90 days');
        // Should have 2 logs: the one created in test + the automatic creation log
        expect(AccessTokenAuditLog::query()->where('token_id', $token->id)->count())->toBe(2);
    });

    it('prunes audit logs from multiple tokens', function (): void {
        // Arrange
        $user = createUser();
        $token1 = createToken($user, 'sk', ['name' => 'Token 1']);
        $token2 = createToken($user, 'sk', ['name' => 'Token 2']);

        // Old logs for both tokens
        AccessTokenAuditLog::query()->create([
            'token_id' => $token1->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(91),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token2->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(92),
        ]);

        // Recent logs
        AccessTokenAuditLog::query()->create([
            'token_id' => $token1->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(10),
        ]);

        // Act
        Artisan::call('bearer:prune-audit-logs');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 2 audit logs older than 90 days');
        // Should have 3 logs: 2 automatic creation logs + 1 recent log from test
        expect(AccessTokenAuditLog::query()->count())->toBe(3);
    });

    it('uses configured retention days from config', function (): void {
        // Arrange
        Config::set('bearer.audit.retention_days', 60);
        $user = createUser();
        $token = createToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(61),
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subDays(59),
        ]);

        // Act
        Artisan::call('bearer:prune-audit-logs');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 1 audit logs older than 60 days');
        // Should have 2 logs: the recent one from test + the automatic creation log
        expect(AccessTokenAuditLog::query()->where('token_id', $token->id)->count())->toBe(2);
    });
});

describe('Prune Expired Command', function (): void {
    it('prunes expired tokens older than threshold', function (): void {
        // Arrange
        $user = createUser();

        // Create expired token (older than 24 hours)
        $expiredToken = createToken($user, 'pk', ['name' => 'Expired Token']);
        $expiredToken->update([
            'expires_at' => now()->subHours(25),
        ]);

        // Create recently expired token (within 24 hours)
        $recentlyExpiredToken = createToken($user, 'pk', ['name' => 'Recently Expired']);
        $recentlyExpiredToken->update([
            'expires_at' => now()->subHours(23),
        ]);

        // Create valid token
        $validToken = createToken($user, 'sk', ['name' => 'Valid Token']);

        $initialCount = $user->tokens()->count();

        // Act
        $exitCode = Artisan::call('bearer:prune-expired');

        // Assert
        expect($exitCode)->toBe(0);
        expect($user->tokens()->count())->toBe($initialCount - 1);
        expect($user->tokens()->find($expiredToken->id))->toBeNull();
        expect($user->tokens()->find($recentlyExpiredToken->id))->not->toBeNull();
        expect($user->tokens()->find($validToken->id))->not->toBeNull();
    });

    it('prunes revoked tokens older than threshold', function (): void {
        // Arrange
        $user = createUser();

        // Create revoked token (older than 24 hours)
        $revokedToken = createToken($user, 'sk', ['name' => 'Revoked Token']);
        $revokedToken->update([
            'revoked_at' => now()->subHours(25),
        ]);

        // Create recently revoked token (within 24 hours)
        $recentlyRevokedToken = createToken($user, 'sk', ['name' => 'Recently Revoked']);
        $recentlyRevokedToken->update([
            'revoked_at' => now()->subHours(23),
        ]);

        // Create valid token
        $validToken = createToken($user, 'sk', ['name' => 'Valid Token']);

        $initialCount = $user->tokens()->count();

        // Act
        $exitCode = Artisan::call('bearer:prune-expired');

        // Assert
        expect($exitCode)->toBe(0);
        expect($user->tokens()->count())->toBe($initialCount - 1);
        expect($user->tokens()->find($revokedToken->id))->toBeNull();
        expect($user->tokens()->find($recentlyRevokedToken->id))->not->toBeNull();
        expect($user->tokens()->find($validToken->id))->not->toBeNull();
    });

    it('respects --hours option override', function (): void {
        // Arrange
        $user = createUser();

        // Create expired token (older than 48 hours)
        $expiredToken = createToken($user, 'pk', ['name' => 'Expired Token']);
        $expiredToken->update([
            'expires_at' => now()->subHours(49),
        ]);

        // Create token expired between 24-48 hours ago
        $recentToken = createToken($user, 'pk', ['name' => 'Recent Token']);
        $recentToken->update([
            'expires_at' => now()->subHours(25),
        ]);

        $initialCount = $user->tokens()->count();

        // Act
        $exitCode = Artisan::call('bearer:prune-expired', ['--hours' => 48]);

        // Assert
        expect($exitCode)->toBe(0);
        expect($user->tokens()->count())->toBe($initialCount - 1);
        expect($user->tokens()->find($expiredToken->id))->toBeNull();
        expect($user->tokens()->find($recentToken->id))->not->toBeNull();
    });

    it('returns SUCCESS exit code', function (): void {
        // Arrange
        $user = createUser();
        $expiredToken = createToken($user, 'pk', ['name' => 'Expired Token']);
        $expiredToken->update([
            'expires_at' => now()->subHours(25),
        ]);

        // Act
        $exitCode = Artisan::call('bearer:prune-expired');

        // Assert
        expect($exitCode)->toBe(0);
    });

    it('does not prune valid tokens', function (): void {
        // Arrange
        $user = createUser();

        // Create valid tokens
        $token1 = createToken($user, 'sk', ['name' => 'Valid Token 1']);
        $token2 = createToken($user, 'sk', ['name' => 'Valid Token 2']);
        $token3 = createToken($user, 'pk', ['name' => 'Valid Token 3']);

        $initialCount = $user->tokens()->count();

        // Act
        $exitCode = Artisan::call('bearer:prune-expired');

        // Assert
        expect($exitCode)->toBe(0);
        expect($user->tokens()->count())->toBe($initialCount);
        expect($user->tokens()->find($token1->id))->not->toBeNull();
        expect($user->tokens()->find($token2->id))->not->toBeNull();
        expect($user->tokens()->find($token3->id))->not->toBeNull();
    });

    it('outputs correct info message', function (): void {
        // Arrange
        $user = createUser();

        $expiredToken1 = createToken($user, 'pk', ['name' => 'Expired 1']);
        $expiredToken1->update(['expires_at' => now()->subHours(25)]);

        $expiredToken2 = createToken($user, 'pk', ['name' => 'Expired 2']);
        $expiredToken2->update(['expires_at' => now()->subHours(30)]);

        // Act
        Artisan::call('bearer:prune-expired');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 2 expired/revoked tokens');
    });

    it('handles case when no tokens need pruning', function (): void {
        // Arrange
        $user = createUser();
        $validToken = createToken($user, 'sk', ['name' => 'Valid Token']);

        $initialCount = $user->tokens()->count();

        // Act
        Artisan::call('bearer:prune-expired');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 0 expired/revoked tokens');
        expect($user->tokens()->count())->toBe($initialCount);
    });

    it('prunes both expired and revoked tokens in single command', function (): void {
        // Arrange
        $user = createUser();

        // Create expired token
        $expiredToken = createToken($user, 'pk', ['name' => 'Expired Token']);
        $expiredToken->update(['expires_at' => now()->subHours(25)]);

        // Create revoked token
        $revokedToken = createToken($user, 'sk', ['name' => 'Revoked Token']);
        $revokedToken->update(['revoked_at' => now()->subHours(25)]);

        // Create valid token
        $validToken = createToken($user, 'sk', ['name' => 'Valid Token']);

        $initialCount = $user->tokens()->count();

        // Act
        Artisan::call('bearer:prune-expired');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 2 expired/revoked tokens');
        expect($user->tokens()->count())->toBe($initialCount - 2);
        expect($user->tokens()->find($expiredToken->id))->toBeNull();
        expect($user->tokens()->find($revokedToken->id))->toBeNull();
        expect($user->tokens()->find($validToken->id))->not->toBeNull();
    });

    it('uses configured expired hours from config', function (): void {
        // Arrange
        Config::set('bearer.prune.expired_hours', 72);
        $user = createUser();

        // Create token expired more than 72 hours ago
        $expiredToken = createToken($user, 'pk', ['name' => 'Expired Token']);
        $expiredToken->update(['expires_at' => now()->subHours(73)]);

        // Create token expired within 72 hours
        $recentToken = createToken($user, 'pk', ['name' => 'Recent Token']);
        $recentToken->update(['expires_at' => now()->subHours(71)]);

        $initialCount = $user->tokens()->count();

        // Act
        Artisan::call('bearer:prune-expired');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 1 expired/revoked tokens');
        expect($user->tokens()->count())->toBe($initialCount - 1);
        expect($user->tokens()->find($expiredToken->id))->toBeNull();
        expect($user->tokens()->find($recentToken->id))->not->toBeNull();
    });

    it('prunes tokens from multiple users', function (): void {
        // Arrange
        $user1 = createUser(['email' => 'user1@example.com']);
        $user2 = createUser(['email' => 'user2@example.com']);

        // Create expired tokens for both users
        $expiredToken1 = createToken($user1, 'pk', ['name' => 'User 1 Expired']);
        $expiredToken1->update(['expires_at' => now()->subHours(25)]);

        $expiredToken2 = createToken($user2, 'pk', ['name' => 'User 2 Expired']);
        $expiredToken2->update(['expires_at' => now()->subHours(25)]);

        // Create valid tokens
        $validToken1 = createToken($user1, 'sk', ['name' => 'User 1 Valid']);
        $validToken2 = createToken($user2, 'sk', ['name' => 'User 2 Valid']);

        // Act
        Artisan::call('bearer:prune-expired');
        $output = Artisan::output();

        // Assert
        expect($output)->toContain('Pruned 2 expired/revoked tokens');
        expect($user1->tokens()->find($expiredToken1->id))->toBeNull();
        expect($user2->tokens()->find($expiredToken2->id))->toBeNull();
        expect($user1->tokens()->find($validToken1->id))->not->toBeNull();
        expect($user2->tokens()->find($validToken2->id))->not->toBeNull();
    });
});
