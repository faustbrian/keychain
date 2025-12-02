<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Enums\RevocationMode;
use Cline\Bearer\Facades\Bearer;
use Illuminate\Support\Sleep;

describe('Token Revocation', function (): void {
    it('revokes a single token', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        Bearer::revoke($token)->revoke();

        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($token->fresh()->revoked_at)->not->toBeNull();
    });

    it('revokes token using model method', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $result = $token->revoke();

        expect($result)->toBeTrue();
        expect($token->isRevoked())->toBeTrue();
    });

    it('cascades revocation to entire group', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');

        Bearer::revoke($group->secretKey())->cascade()->revoke();

        expect($group->fresh()->secretKey()->isRevoked())->toBeTrue();
        expect($group->fresh()->publishableKey()->isRevoked())->toBeTrue();
        expect($group->fresh()->restrictedKey()->isRevoked())->toBeTrue();
    });

    it('partial cascade revokes only server-side tokens', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');

        Bearer::revoke($group->secretKey())->using(RevocationMode::Partial)->revoke();

        expect($group->secretKey()->fresh()->isRevoked())->toBeTrue();
        expect($group->restrictedKey()->fresh()->isRevoked())->toBeTrue();
        expect($group->publishableKey()->fresh()->isRevoked())->toBeFalse();
    });

    it('does not cascade revocation with none mode', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');

        Bearer::revoke($group->secretKey())->revoke();

        expect($group->secretKey()->fresh()->isRevoked())->toBeTrue();
        expect($group->publishableKey()->fresh()->isRevoked())->toBeFalse();
        expect($group->restrictedKey()->fresh()->isRevoked())->toBeFalse();
    });

    it('revokes all tokens in group via model method', function (): void {
        $user = createUser();
        $group = Bearer::for($user)->issueGroup(['sk', 'pk', 'rk'], 'Keys');

        $count = $group->revokeAll();

        expect($count)->toBe(3);
        expect($group->fresh()->accessTokens->every->isRevoked())->toBeTrue();
    });

    it('identifies revoked tokens correctly', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($token->isRevoked())->toBeFalse();
        expect($token->isValid())->toBeTrue();

        $token->revoke();

        expect($token->isRevoked())->toBeTrue();
        expect($token->isValid())->toBeFalse();
    });

    it('does not affect other user tokens', function (): void {
        $user1 = createUser(['email' => 'user1@example.com']);
        $user2 = createUser(['email' => 'user2@example.com']);

        $token1 = createAccessToken($user1);
        $token2 = createAccessToken($user2);

        Bearer::revoke($token1)->revoke();

        expect($token1->fresh()->isRevoked())->toBeTrue();
        expect($token2->fresh()->isRevoked())->toBeFalse();
    });

    it('does not affect tokens in different groups', function (): void {
        $user = createUser();
        $group1 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
        $group2 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

        Bearer::revoke($group1->secretKey())->cascade()->revoke();

        expect($group1->fresh()->accessTokens->every->isRevoked())->toBeTrue();
        expect($group2->fresh()->accessTokens->every->isRevoked())->toBeFalse();
    });

    it('handles ungrouped token revocation', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($token->group_id)->toBeNull();

        Bearer::revoke($token)->cascade()->revoke();

        expect($token->fresh()->isRevoked())->toBeTrue();
    });

    it('can revoke expired token', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->expiresIn(-10)
            ->issue('sk', 'Expired Key')
            ->accessToken;

        expect($token->isExpired())->toBeTrue();

        Bearer::revoke($token)->revoke();

        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($token->fresh()->isExpired())->toBeTrue();
    });

    it('preserves revoked state on refresh', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $token->revoke();

        $freshToken = $token->fresh();

        expect($freshToken->isRevoked())->toBeTrue();
        expect($freshToken->revoked_at)->not->toBeNull();
    });

    it('allows multiple revocation calls idempotently', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $token->revoke();

        $firstRevokedAt = $token->revoked_at;

        Sleep::sleep(1);
        $token->fresh()->revoke();

        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($token->fresh()->revoked_at)->not->toBe($firstRevokedAt);
    });

    it('handles timed revocation mode', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        Bearer::revoke($token)->using(RevocationMode::Timed)->revoke();

        expect($token->fresh()->isRevoked())->toBeTrue();
    });
});
