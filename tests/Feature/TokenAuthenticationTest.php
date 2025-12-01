<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\TransientToken;

describe('Token Authentication', function (): void {
    it('authenticates user with valid token', function (): void {
        $user = createUser();
        $newToken = Bearer::for($user)->issue('sk', 'API Key');

        $authenticatedToken = Bearer::findAccessToken($newToken->plainTextAccessToken);

        expect($authenticatedToken)->not->toBeNull();
        expect($authenticatedToken->owner_id)->toBe($user->id);
    });

    it('returns null for invalid token', function (): void {
        $result = Bearer::findAccessToken('invalid_token_string');

        expect($result)->toBeNull();
    });

    it('validates token by prefix', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'API Key');

        $found = Bearer::findByPrefix($token->accessToken->prefix);

        expect($found)->not->toBeNull();
        expect($found->prefix)->toBe($token->accessToken->prefix);
    });

    it('checks token abilities', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->abilities(['users:read', 'posts:write'])
            ->issue('sk', 'Scoped Key')
            ->accessToken;

        expect($token->can('users:read'))->toBeTrue();
        expect($token->can('posts:write'))->toBeTrue();
        expect($token->can('posts:delete'))->toBeFalse();
        expect($token->cant('posts:delete'))->toBeTrue();
    });

    it('grants all abilities with wildcard', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->abilities(['*'])
            ->issue('sk', 'Admin Key')
            ->accessToken;

        expect($token->can('any:random:ability'))->toBeTrue();
        expect($token->cant('any:random:ability'))->toBeFalse();
    });

    it('identifies expired tokens', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->expiresIn(-10)
            ->issue('sk', 'Expired Key')
            ->accessToken;

        expect($token->isExpired())->toBeTrue();
        expect($token->isValid())->toBeFalse();
    });

    it('identifies non-expired tokens', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->expiresIn(60)
            ->issue('sk', 'Valid Key')
            ->accessToken;

        expect($token->isExpired())->toBeFalse();
        expect($token->isValid())->toBeTrue();
    });

    it('identifies revoked tokens', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($token->isRevoked())->toBeFalse();

        $token->revoke();

        expect($token->isRevoked())->toBeTrue();
        expect($token->isValid())->toBeFalse();
    });

    it('validates token is invalid when revoked or expired', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($token->isValid())->toBeTrue();

        $token->revoke();
        expect($token->isValid())->toBeFalse();
    });

    it('uses actingAs for testing', function (): void {
        $user = createUser();

        Bearer::actingAs($user, ['users:read', 'posts:write'], 'sk');

        expect($user->currentAccessToken())->not->toBeNull();
        expect($user->accessTokenCan('users:read'))->toBeTrue();
        expect($user->accessTokenCan('posts:write'))->toBeTrue();
        expect($user->accessTokenCan('posts:delete'))->toBeFalse();
    });

    it('uses actingAs with wildcard abilities', function (): void {
        $user = createUser();

        Bearer::actingAs($user, ['*']);

        expect($user->accessTokenCan('any:ability'))->toBeTrue();
    });

    it('attaches token to user model', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $user->withAccessToken($token);

        expect($user->currentAccessToken())->toBe($token);
    });

    it('checks token type on user', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'Secret')->accessToken;

        $user->withAccessToken($token);

        expect($user->tokenIs('sk'))->toBeTrue();
        expect($user->tokenIs('pk'))->toBeFalse();
        expect($user->tokenType())->toBe('sk');
    });

    it('checks token environment on user', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->environment('production')
            ->issue('sk', 'Prod Key')
            ->accessToken;

        $user->withAccessToken($token);

        expect($user->tokenEnvironment())->toBe('production');
    });

    it('returns null when no token attached', function (): void {
        $user = createUser();

        expect($user->currentAccessToken())->toBeNull();
        expect($user->accessTokenCan('any:ability'))->toBeFalse();
        expect($user->accessTokenCant('any:ability'))->toBeTrue();
        expect($user->tokenIs('sk'))->toBeFalse();
        expect($user->tokenEnvironment())->toBeNull();
        expect($user->tokenType())->toBeNull();
    });

    it('uses transient token for session authentication', function (): void {
        $user = createUser();
        $transientToken = new TransientToken();

        $user->withAccessToken($transientToken);

        expect($user->accessTokenCan('any:ability'))->toBeTrue();
        expect($user->accessTokenCant('any:ability'))->toBeFalse();
        expect($user->tokenIs('sk'))->toBeFalse();
    });

    it('finds token using findAccessToken method', function (): void {
        $user = createUser();
        $newToken = Bearer::for($user)->issue('sk', 'Test');

        $found = Bearer::findAccessToken($newToken->plainTextAccessToken);

        expect($found)->not->toBeNull();
        expect($found->name)->toBe('Test');
    });

    it('hashes token for secure storage', function (): void {
        $user = createUser();
        $newToken = Bearer::for($user)->issue('sk', 'Test');

        $storedHash = $newToken->accessToken->token;
        $expectedHash = hash('sha256', $newToken->plainTextAccessToken);

        expect($storedHash)->toBe($expectedHash);
    });

    it('tracks last_used_at timestamp', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($token->last_used_at)->toBeNull();

        $token->update(['last_used_at' => now()]);
        $token->refresh();

        expect($token->last_used_at)->not->toBeNull();
    });

    it('creates multiple tokens for same user', function (): void {
        $user = createUser();

        $token1 = Bearer::for($user)->issue('sk', 'Token 1');
        $token2 = Bearer::for($user)->issue('pk', 'Token 2');
        $token3 = Bearer::for($user)->issue('rk', 'Token 3');

        expect($user->accessTokens()->count())->toBe(3);
    });

    it('filters tokens by type', function (): void {
        $user = createUser();

        Bearer::for($user)->issue('sk', 'Secret 1');
        Bearer::for($user)->issue('sk', 'Secret 2');
        Bearer::for($user)->issue('pk', 'Publishable');

        $secretKeys = $user->accessTokens()->where('type', 'sk')->get();

        expect($secretKeys)->toHaveCount(2);
    });

    it('filters tokens by environment', function (): void {
        $user = createUser();

        Bearer::for($user)->environment('production')->issue('sk', 'Prod 1');
        Bearer::for($user)->environment('production')->issue('sk', 'Prod 2');
        Bearer::for($user)->environment('development')->issue('sk', 'Dev');

        $prodTokens = $user->accessTokens()->where('environment', 'production')->get();

        expect($prodTokens)->toHaveCount(2);
    });

    it('deletes tokens for user', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        expect($user->accessTokens()->count())->toBe(1);

        $token->delete();

        expect($user->accessTokens()->count())->toBe(0);
    });

    it('cascades token deletion when user is deleted', function (): void {
        $user = createUser();
        createAccessToken($user);
        createAccessToken($user);

        $tokenCount = $user->accessTokens()->count();
        expect($tokenCount)->toBe(2);

        $user->delete();

        expect($user->accessTokens()->count())->toBe(0);
    });
});
