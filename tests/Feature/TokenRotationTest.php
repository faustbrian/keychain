<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\NewAccessToken;

describe('Token Rotation', function (): void {
    it('rotates a token with immediate invalidation', function (): void {
        $user = createUser();
        $oldToken = createAccessToken($user);
        $oldPlainText = 'original_token';

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($newToken->plainTextAccessToken)->not->toBe($oldPlainText);
        expect($oldToken->fresh()->isRevoked())->toBeTrue();
    });

    it('creates new token with same configuration', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->abilities(['users:read', 'posts:write'])
            ->environment('production')
            ->issue('sk', 'Original Key')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->type)->toBe($oldToken->type);
        expect($newToken->accessToken->name)->toBe($oldToken->name);
        expect($newToken->accessToken->abilities)->toBe($oldToken->abilities);
        expect($newToken->accessToken->environment)->toBe($oldToken->environment);
        expect($newToken->accessToken->owner_id)->toBe($oldToken->owner_id);
    });

    it('preserves IP restrictions on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->allowedIps(['192.168.1.1', '10.0.0.1'])
            ->issue('sk', 'IP Restricted')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->allowed_ips)->toBe($oldToken->allowed_ips);
    });

    it('preserves domain restrictions on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->allowedDomains(['example.com', 'app.example.com'])
            ->issue('pk', 'Domain Restricted')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->allowed_domains)->toBe($oldToken->allowed_domains);
    });

    it('preserves rate limit on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->rateLimit(100)
            ->issue('sk', 'Rate Limited')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->rate_limit_per_minute)->toBe($oldToken->rate_limit_per_minute);
    });

    it('preserves metadata on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->metadata(['app' => 'mobile', 'version' => '2.0'])
            ->issue('sk', 'Metadata Key')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->metadata)->toBe($oldToken->metadata);
    });

    it('maintains group association on rotation', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Rotatable Keys');
        $oldToken = $group->secretKey();

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->group_id)->toBe($group->id);
        expect($group->fresh()->accessTokens)->toHaveCount(3);
    });

    it('rotates with grace period mode', function (): void {
        $user = createUser();
        $oldToken = createAccessToken($user);

        $newToken = Bearer::rotate($oldToken, 'grace_period');

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($newToken->plainTextAccessToken)->not->toBe($oldToken->token);
    });

    it('rotates with dual valid mode', function (): void {
        $user = createUser();
        $oldToken = createAccessToken($user);

        $newToken = Bearer::rotate($oldToken, 'dual_valid');

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($oldToken->fresh()->isRevoked())->toBeFalse();
        expect($newToken->accessToken->isValid())->toBeTrue();
    });

    it('generates unique token on rotation', function (): void {
        $user = createUser();
        $token = createAccessToken($user);
        $originalHash = $token->token;

        $newToken = Bearer::rotate($token, 'immediate');

        expect($newToken->accessToken->token)->not->toBe($originalHash);
        expect($newToken->plainTextAccessToken)->not->toContain($originalHash);
    });

    it('resets last_used_at on rotation', function (): void {
        $user = createUser();
        $oldToken = createAccessToken($user);
        $oldToken->update(['last_used_at' => now()->subHours(5)]);

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->last_used_at)->toBeNull();
    });

    it('does not preserve expiration on rotation', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->expiresIn(60)
            ->issue('sk', 'Expiring Key')
            ->accessToken;

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->expires_at)->toBeNull();
    });

    it('can rotate already revoked token', function (): void {
        $user = createUser();
        $oldToken = createAccessToken($user);
        $oldToken->revoke();

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken)->toBeInstanceOf(NewAccessToken::class);
        expect($newToken->accessToken->isRevoked())->toBeFalse();
    });

    it('can rotate expired token', function (): void {
        $user = createUser();
        $oldToken = Bearer::for($user)
            ->expiresIn(-10)
            ->issue('sk', 'Expired')
            ->accessToken;

        expect($oldToken->isExpired())->toBeTrue();

        $newToken = Bearer::rotate($oldToken, 'immediate');

        expect($newToken->accessToken->isExpired())->toBeFalse();
    });

    it('rotates multiple times sequentially', function (): void {
        $user = createUser();
        $token1 = createAccessToken($user);

        $token2 = Bearer::rotate($token1, 'immediate');
        $token3 = Bearer::rotate($token2->accessToken, 'immediate');

        expect($token1->fresh()->isRevoked())->toBeTrue();
        expect($token2->accessToken->fresh()->isRevoked())->toBeTrue();
        expect($token3->accessToken->isRevoked())->toBeFalse();
    });

    it('increments user token count on rotation with dual valid', function (): void {
        $user = createUser();
        $initialCount = $user->accessTokens()->count();
        $oldToken = createAccessToken($user);

        Bearer::rotate($oldToken, 'dual_valid');

        expect($user->fresh()->accessTokens()->count())->toBe($initialCount + 2);
    });

    it('maintains same token count on rotation with immediate', function (): void {
        $user = createUser();
        $token = createAccessToken($user);
        $countAfterCreate = $user->accessTokens()->count();

        Bearer::rotate($token, 'immediate');

        expect($user->fresh()->accessTokens()->count())->toBe($countAfterCreate + 1);
    });
});
