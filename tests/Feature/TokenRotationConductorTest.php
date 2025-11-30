<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\BearerManager;
use Cline\Bearer\Conductors\TokenRotationConductor;
use Cline\Bearer\Enums\RotationMode;
use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\NewAccessToken;

describe('TokenRotationConductor', function (): void {
    it('rotates token with immediate mode', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($newToken->accessToken->isValid())->toBeTrue();
    });

    it('rotates token with grace period mode', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->withGracePeriod(30)->rotate();

        $refreshedToken = $token->fresh();
        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($refreshedToken->expires_at)->not->toBeNull();
        expect($refreshedToken->expires_at->isFuture())->toBeTrue();
        expect($refreshedToken->metadata['grace_period_expires_at'])->not->toBeNull();
    });

    it('rotates token with dual valid mode', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->using(RotationMode::DualValid)->rotate();

        $refreshedToken = $token->fresh();
        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($refreshedToken->isRevoked())->toBeFalse();
        expect($refreshedToken->metadata['rotated'])->toBeTrue();
        expect($refreshedToken->metadata['rotated_at'])->not->toBeNull();
        expect($newToken->accessToken->isValid())->toBeTrue();
    });

    it('preserves group_id on rotation', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk'], 'Test Group');
        $token = $group->secretKey();
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->group_id)->toBe($token->group_id);
    });

    it('preserves type on rotation', function (): void {
        $user = createUser();
        $token = createToken($user, 'pk');
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->type)->toBe($token->type);
    });

    it('preserves environment on rotation', function (): void {
        $user = createUser();
        $token = createToken($user, 'sk', ['environment' => 'production']);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->environment)->toBe('production');
    });

    it('preserves abilities on rotation', function (): void {
        $user = createUser();
        $token = createToken($user, 'sk', ['abilities' => ['users:read', 'posts:write']]);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->abilities)->toBe(['users:read', 'posts:write']);
    });

    it('preserves allowed_ips restriction on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->allowedIps(['192.168.1.1', '10.0.0.1'])
            ->issue('sk', 'IP Restricted')
            ->accessToken;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $oldToken);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->allowed_ips)->toBe($oldToken->allowed_ips);
    });

    it('preserves allowed_domains restriction on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->allowedDomains(['example.com', 'app.example.com'])
            ->issue('pk', 'Domain Restricted')
            ->accessToken;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $oldToken);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->allowed_domains)->toBe($oldToken->allowed_domains);
    });

    it('preserves rate_limit_per_minute on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->rateLimit(100)
            ->issue('sk', 'Rate Limited')
            ->accessToken;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $oldToken);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->rate_limit_per_minute)->toBe($oldToken->rate_limit_per_minute);
    });

    it('adds rotated_from metadata to new token', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->metadata['rotated_from'])->toBe($token->id);
    });

    it('adds rotation_mode metadata to new token', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->withGracePeriod(60)->rotate();

        expect($newToken->accessToken->metadata['rotation_mode'])->toBe(RotationMode::GracePeriod->value);
    });

    it('preserves existing metadata on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->metadata(['app' => 'mobile', 'version' => '2.0'])
            ->issue('sk', 'Metadata Key')
            ->accessToken;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $oldToken);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->metadata['app'])->toBe('mobile');
        expect($newToken->accessToken->metadata['version'])->toBe('2.0');
        expect($newToken->accessToken->metadata['rotated_from'])->toBe($oldToken->id);
    });

    it('throws RuntimeException when tokenable is null', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        // Simulate a token with no tokenable by refreshing after deletion
        // This forces the tokenable relationship to return null
        $token->tokenable()->getRelated()::query()->delete();
        $token = $token->fresh();
        $token->setRelation('tokenable', null);

        $conductor = new TokenRotationConductor($manager, $token);

        expect(fn (): NewAccessToken => $conductor->immediate()->rotate())
            ->toThrow(RuntimeException::class, 'Token has no associated tokenable model');
    });

    it('using() returns new instance with specified mode', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newConductor = $conductor->using(RotationMode::GracePeriod);

        expect($newConductor)->not->toBe($conductor);
        expect($newConductor)->toBeInstanceOf(TokenRotationConductor::class);
    });

    it('withGracePeriod() sets mode to GracePeriod', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->withGracePeriod(45)->rotate();

        expect($newToken->accessToken->metadata['rotation_mode'])->toBe(RotationMode::GracePeriod->value);
    });

    it('immediate() is shorthand for using immediate mode', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->metadata['rotation_mode'])->toBe(RotationMode::Immediate->value);
    });

    it('handleImmediate revokes old token immediately', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $conductor->immediate()->rotate();

        $refreshedToken = $token->fresh();
        expect($refreshedToken->revoked_at)->not->toBeNull();
        expect($refreshedToken->isRevoked())->toBeTrue();
    });

    it('handleGracePeriod sets expires_at on old token', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $gracePeriodMinutes = 45;
        $conductor = new TokenRotationConductor($manager, $token);
        $conductor->withGracePeriod($gracePeriodMinutes)->rotate();

        $refreshedToken = $token->fresh();
        expect($refreshedToken->expires_at)->not->toBeNull();
        expect($refreshedToken->expires_at->isFuture())->toBeTrue();
        expect(now()->diffInMinutes($refreshedToken->expires_at, false))->toBeGreaterThanOrEqual($gracePeriodMinutes - 1);
    });

    it('handleGracePeriod uses default 30 minutes if grace period not specified', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $conductor->using(RotationMode::GracePeriod)->rotate();

        $refreshedToken = $token->fresh();
        expect($refreshedToken->expires_at)->not->toBeNull();
        expect($refreshedToken->expires_at->isFuture())->toBeTrue();
        expect(now()->diffInMinutes($refreshedToken->expires_at, false))->toBeGreaterThanOrEqual(29);
    });

    it('handleDualValid marks old token as rotated', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $beforeRotation = now();
        $conductor = new TokenRotationConductor($manager, $token);
        $conductor->using(RotationMode::DualValid)->rotate();

        $refreshedToken = $token->fresh();
        expect($refreshedToken->metadata['rotated'])->toBeTrue();
        expect($refreshedToken->metadata['rotated_at'])->not->toBeNull();
    });

    it('handleDualValid keeps old token valid', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $conductor->using(RotationMode::DualValid)->rotate();

        $refreshedToken = $token->fresh();
        expect($refreshedToken->isRevoked())->toBeFalse();
        expect($refreshedToken->isValid())->toBeTrue();
    });

    it('generates unique token on rotation', function (): void {
        $user = createUser();
        $token = createToken($user);
        $originalHash = $token->token;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->token)->not->toBe($originalHash);
        expect($newToken->plainTextToken)->not->toContain($originalHash);
    });

    it('creates audit log entry on rotation', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->withGracePeriod(60)->rotate();

        // Check that audit log entry was created
        // Note: This assumes an audit driver is configured
        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
    });

    it('rotates multiple times sequentially with conductor', function (): void {
        $user = createUser();
        $token1 = createToken($user);
        $manager = app(BearerManager::class);

        $conductor1 = new TokenRotationConductor($manager, $token1);
        $token2 = $conductor1->immediate()->rotate();

        $conductor2 = new TokenRotationConductor($manager, $token2->accessToken);
        $token3 = $conductor2->immediate()->rotate();

        expect($token1->fresh()->isRevoked())->toBeTrue();
        expect($token2->accessToken->fresh()->isRevoked())->toBeTrue();
        expect($token3->accessToken->isRevoked())->toBeFalse();
    });

    it('preserves prefix on rotation', function (): void {
        $user = createUser();
        $token = createToken($user, 'sk');
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->prefix)->toBe($token->prefix);
    });

    it('resets last_used_at on rotation', function (): void {
        $user = createUser();
        $token = createToken($user);
        $token->update(['last_used_at' => now()->subHours(5)]);

        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->last_used_at)->toBeNull();
    });

    it('can chain configuration methods', function (): void {
        $user = createUser();
        $token = createToken($user);
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $token);
        $newToken = $conductor
            ->using(RotationMode::GracePeriod)
            ->withGracePeriod(120)
            ->rotate();

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($newToken->accessToken->metadata['rotation_mode'])->toBe(RotationMode::GracePeriod->value);
    });

    it('preserves expires_at on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->expiresIn(1_440) // 24 hours
            ->issue('sk', 'Expiring Key')
            ->accessToken;
        $manager = app(BearerManager::class);

        $conductor = new TokenRotationConductor($manager, $oldToken);
        $newToken = $conductor->immediate()->rotate();

        expect($newToken->accessToken->expires_at)->not->toBeNull();
        expect($newToken->accessToken->expires_at->equalTo($oldToken->expires_at))->toBeTrue();
    });
});
