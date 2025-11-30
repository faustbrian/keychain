<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\NewAccessToken;

describe('Token Issuance', function (): void {
    it('issues a single token', function (): void {
        $user = createUser();

        $result = Bearer::for($user)->issue(
            type: 'sk',
            name: 'My API Key',
        );

        expect($result)->toBeInstanceOf(NewAccessToken::class);
        expect($result->plainTextToken)->toStartWith('sk_test_');
        expect($result->accessToken->name)->toBe('My API Key');
        expect($result->accessToken->type)->toBe('sk');
    });

    it('issues a token group', function (): void {
        $user = createUser();

        $group = Bearer::for($user)->issueGroup(
            types: ['sk', 'pk', 'rk'],
            name: 'Production Keys',
        );

        expect($group->tokens)->toHaveCount(3);
        expect($group->secretKey())->not->toBeNull();
        expect($group->publishableKey())->not->toBeNull();
        expect($group->restrictedKey())->not->toBeNull();
    });

    it('respects IP restrictions', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->allowedIps(['192.168.1.0/24'])
            ->issue('sk', 'Restricted Key');

        expect($result->accessToken->allowed_ips)->toBe(['192.168.1.0/24']);
    });

    it('respects domain restrictions', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->allowedDomains(['*.example.com'])
            ->issue('pk', 'Frontend Key');

        expect($result->accessToken->allowed_domains)->toBe(['*.example.com']);
    });

    it('sets token abilities', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->abilities(['users:read', 'posts:write'])
            ->issue('sk', 'API Key');

        expect($result->accessToken->abilities)->toBe(['users:read', 'posts:write']);
        expect($result->accessToken->can('users:read'))->toBeTrue();
        expect($result->accessToken->can('posts:write'))->toBeTrue();
        expect($result->accessToken->cant('users:delete'))->toBeTrue();
    });

    it('sets wildcard abilities', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->abilities(['*'])
            ->issue('sk', 'Admin Key');

        expect($result->accessToken->can('any:ability'))->toBeTrue();
    });

    it('sets token environment', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->environment('production')
            ->issue('sk', 'Production Key');

        expect($result->accessToken->environment)->toBe('production');
    });

    it('sets expiration timestamp', function (): void {
        $user = createUser();
        $expiresAt = now()->addDays(30);

        $result = Bearer::for($user)
            ->expiresAt($expiresAt)
            ->issue('sk', 'Temporary Key');

        expect($result->accessToken->expires_at->toDateTimeString())
            ->toBe($expiresAt->toDateTimeString());
    });

    it('sets expiration in minutes', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->expiresIn(60)
            ->issue('sk', 'Short-lived Key');

        expect($result->accessToken->expires_at)->not->toBeNull();
        expect($result->accessToken->expires_at->isFuture())->toBeTrue();
    });

    it('sets rate limit', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->rateLimit(100)
            ->issue('sk', 'Rate-limited Key');

        expect($result->accessToken->rate_limit_per_minute)->toBe(100);
    });

    it('sets metadata', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->metadata(['app' => 'mobile', 'version' => '1.0'])
            ->issue('sk', 'Mobile Key');

        expect($result->accessToken->metadata)->toBe(['app' => 'mobile', 'version' => '1.0']);
    });

    it('generates unique tokens', function (): void {
        $user = createUser();

        $token1 = Bearer::for($user)->issue('sk', 'Token 1');
        $token2 = Bearer::for($user)->issue('sk', 'Token 2');

        expect($token1->plainTextToken)->not->toBe($token2->plainTextToken);
        expect($token1->accessToken->token)->not->toBe($token2->accessToken->token);
    });

    it('stores hashed token', function (): void {
        $user = createUser();

        $result = Bearer::for($user)->issue('sk', 'API Key');

        expect($result->accessToken->token)->not->toBe($result->plainTextToken);
        expect($result->accessToken->token)->toBe(hash('sha256', $result->plainTextToken));
    });

    it('assigns correct token prefix based on type', function (): void {
        $user = createUser();

        $secretKey = Bearer::for($user)->issue('sk', 'Secret');
        $publishableKey = Bearer::for($user)->issue('pk', 'Publishable');
        $restrictedKey = Bearer::for($user)->issue('rk', 'Restricted');

        expect($secretKey->plainTextToken)->toStartWith('sk_test_');
        expect($publishableKey->plainTextToken)->toStartWith('pk_test_');
        expect($restrictedKey->plainTextToken)->toStartWith('rk_test_');

        expect($secretKey->accessToken->prefix)->toBe('sk');
        expect($publishableKey->accessToken->prefix)->toBe('pk');
        expect($restrictedKey->accessToken->prefix)->toBe('rk');
    });

    it('overrides default configuration with method parameters', function (): void {
        $user = createUser();

        $result = Bearer::for($user)
            ->abilities(['default:ability'])
            ->environment('staging')
            ->issue(
                type: 'sk',
                name: 'Override Key',
                abilities: ['override:ability'],
                environment: 'production',
            );

        expect($result->accessToken->abilities)->toBe(['override:ability']);
        expect($result->accessToken->environment)->toBe('production');
    });

    it('creates token group with shared configuration', function (): void {
        $user = createUser();

        $group = Bearer::for($user)
            ->abilities(['users:read'])
            ->environment('production')
            ->issueGroup(
                types: ['sk', 'pk'],
                name: 'Shared Config',
            );

        expect($group->secretKey()->abilities)->toBe(['users:read']);
        expect($group->secretKey()->environment)->toBe('production');
        expect($group->publishableKey()->abilities)->toBe(['users:read']);
        expect($group->publishableKey()->environment)->toBe('production');
    });

    it('links tokens to group', function (): void {
        $user = createUser();

        $group = Bearer::for($user)->issueGroup(
            types: ['sk', 'pk'],
            name: 'Linked Keys',
        );

        $secretKey = $group->secretKey();
        $publishableKey = $group->publishableKey();

        expect($secretKey->group_id)->toBe($group->id);
        expect($publishableKey->group_id)->toBe($group->id);
        expect($secretKey->group->id)->toBe($group->id);
    });

    it('finds sibling tokens within group', function (): void {
        $user = createUser();

        $group = Bearer::for($user)->issueGroup(
            types: ['sk', 'pk', 'rk'],
            name: 'Sibling Keys',
        );

        $secretKey = $group->secretKey();
        $publishableKey = $secretKey->sibling('pk');
        $restrictedKey = $secretKey->sibling('rk');

        expect($publishableKey)->not->toBeNull();
        expect($publishableKey->type)->toBe('pk');
        expect($restrictedKey)->not->toBeNull();
        expect($restrictedKey->type)->toBe('rk');
    });
});
