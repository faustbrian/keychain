<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Conductors\TokenQueryConductor;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Facades\Bearer;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Sleep;

describe('TokenQueryConductor', function (): void {
    describe('type()', function (): void {
        it('filters tokens by type', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Secret Key']);
            createAccessToken($user, 'pk', ['name' => 'Publishable Key']);
            createAccessToken($user, 'rk', ['name' => 'Restricted Key']);

            // Act
            $secretKeys = new TokenQueryConductor($user)->type('sk')->get();
            $publishableKeys = new TokenQueryConductor($user)->type('pk')->get();

            // Assert
            expect($secretKeys)->toHaveCount(1);
            expect($secretKeys->first()->type)->toBe('sk');
            expect($publishableKeys)->toHaveCount(1);
            expect($publishableKeys->first()->type)->toBe('pk');
        });

        it('returns empty collection when no tokens match type', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk');

            // Act
            $result = new TokenQueryConductor($user)->type('nonexistent')->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('environment()', function (): void {
        it('filters tokens by environment', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['environment' => 'production']);
            createAccessToken($user, 'sk', ['environment' => 'staging']);
            createAccessToken($user, 'sk', ['environment' => 'development']);

            // Act
            $productionTokens = new TokenQueryConductor($user)->environment('production')->get();
            $stagingTokens = new TokenQueryConductor($user)->environment('staging')->get();

            // Assert
            expect($productionTokens)->toHaveCount(1);
            expect($productionTokens->first()->environment)->toBe('production');
            expect($stagingTokens)->toHaveCount(1);
            expect($stagingTokens->first()->environment)->toBe('staging');
        });

        it('returns empty collection when no tokens match environment', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['environment' => 'production']);

            // Act
            $result = new TokenQueryConductor($user)->environment('nonexistent')->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('valid()', function (): void {
        it('returns only non-expired and non-revoked tokens', function (): void {
            // Arrange
            $user = createUser();
            $validToken = createAccessToken($user, 'sk', ['name' => 'Valid Token']);

            $expiredToken = Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired Token');

            $revokedToken = createAccessToken($user, 'sk', ['name' => 'Revoked Token']);
            $revokedToken->revoke();

            // Act
            $result = new TokenQueryConductor($user)->valid()->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->id)->toBe($validToken->id);
            expect($result->first()->name)->toBe('Valid Token');
        });

        it('includes tokens with no expiration date', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Never Expires']);

            // Act
            $result = new TokenQueryConductor($user)->valid()->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->expires_at)->toBeNull();
        });

        it('includes tokens with future expiration date', function (): void {
            // Arrange
            $user = createUser();
            Bearer::for($user)
                ->expiresAt(now()->addDay())
                ->issue('sk', 'Future Expiration');

            // Act
            $result = new TokenQueryConductor($user)->valid()->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->expires_at->isFuture())->toBeTrue();
        });

        it('excludes tokens that are both expired and revoked', function (): void {
            // Arrange
            $user = createUser();
            $token = Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired and Revoked');
            $token->accessToken->revoke();

            // Act
            $result = new TokenQueryConductor($user)->valid()->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('expired()', function (): void {
        it('returns only expired tokens', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Valid Token']);

            Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired Token 1');

            Bearer::for($user)
                ->expiresAt(now()->subHour())
                ->issue('sk', 'Expired Token 2');

            // Act
            $result = new TokenQueryConductor($user)->expired()->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('name'))->toContain('Expired Token 1', 'Expired Token 2');
        });

        it('excludes tokens with no expiration date', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Never Expires']);

            // Act
            $result = new TokenQueryConductor($user)->expired()->get();

            // Assert
            expect($result)->toHaveCount(0);
        });

        it('excludes tokens with future expiration', function (): void {
            // Arrange
            $user = createUser();
            Bearer::for($user)
                ->expiresAt(now()->addDay())
                ->issue('sk', 'Future Expiration');

            // Act
            $result = new TokenQueryConductor($user)->expired()->get();

            // Assert
            expect($result)->toHaveCount(0);
        });

        it('includes revoked tokens if they are also expired', function (): void {
            // Arrange
            $user = createUser();
            $token = Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired and Revoked');
            $token->accessToken->revoke();

            // Act
            $result = new TokenQueryConductor($user)->expired()->get();

            // Assert
            expect($result)->toHaveCount(1);
        });
    });

    describe('revoked()', function (): void {
        it('returns only revoked tokens', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Active Token']);

            $revokedToken1 = createAccessToken($user, 'sk', ['name' => 'Revoked Token 1']);
            $revokedToken1->revoke();

            $revokedToken2 = createAccessToken($user, 'sk', ['name' => 'Revoked Token 2']);
            $revokedToken2->revoke();

            // Act
            $result = new TokenQueryConductor($user)->revoked()->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('name'))->toContain('Revoked Token 1', 'Revoked Token 2');
        });

        it('excludes non-revoked tokens', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Active Token']);

            // Act
            $result = new TokenQueryConductor($user)->revoked()->get();

            // Assert
            expect($result)->toHaveCount(0);
        });

        it('includes expired tokens if they are also revoked', function (): void {
            // Arrange
            $user = createUser();
            $token = Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired and Revoked');
            $token->accessToken->revoke();

            // Act
            $result = new TokenQueryConductor($user)->revoked()->get();

            // Assert
            expect($result)->toHaveCount(1);
        });
    });

    describe('group()', function (): void {
        it('filters tokens by group_id', function (): void {
            // Arrange
            $user = createUser();

            $group1 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            $group2 = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 2');

            // Act
            $group1Tokens = new TokenQueryConductor($user)->group($group1->id)->get();
            $group2Tokens = new TokenQueryConductor($user)->group($group2->id)->get();

            // Assert
            expect($group1Tokens)->toHaveCount(2);
            expect($group1Tokens->pluck('group_id')->unique()->first())->toBe($group1->id);
            expect($group2Tokens)->toHaveCount(2);
            expect($group2Tokens->pluck('group_id')->unique()->first())->toBe($group2->id);
        });

        it('accepts string group_id', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(['sk', 'pk'], 'Test Group');

            // Act
            $result = new TokenQueryConductor($user)->group((string) $group->id)->get();

            // Assert
            expect($result)->toHaveCount(2);
        });

        it('returns empty collection when no tokens match group_id', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk');

            // Act
            $result = new TokenQueryConductor($user)->group(999_999)->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('ungrouped()', function (): void {
        it('returns only tokens without a group', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', ['name' => 'Standalone Token 1']);
            createAccessToken($user, 'pk', ['name' => 'Standalone Token 2']);

            Bearer::for($user)->issueGroup(['sk', 'pk'], 'Grouped Tokens');

            // Act
            $result = new TokenQueryConductor($user)->ungrouped()->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('name'))->toContain('Standalone Token 1', 'Standalone Token 2');
            expect($result->pluck('group_id')->unique()->first())->toBeNull();
        });

        it('returns empty collection when all tokens are grouped', function (): void {
            // Arrange
            $user = createUser();
            Bearer::for($user)->issueGroup(['sk', 'pk'], 'Group 1');
            Bearer::for($user)->issueGroup(['rk'], 'Group 2');

            // Act
            $result = new TokenQueryConductor($user)->ungrouped()->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('withAbility()', function (): void {
        it('filters tokens with specific ability', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', [
                'name' => 'Read Token',
                'abilities' => ['users:read'],
            ]);

            createAccessToken($user, 'sk', [
                'name' => 'Write Token',
                'abilities' => ['users:write'],
            ]);

            // Act
            $result = new TokenQueryConductor($user)->withAbility('users:read')->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->name)->toBe('Read Token');
            expect($result->first()->abilities)->toContain('users:read');
        });

        it('includes tokens with wildcard ability', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', [
                'name' => 'Admin Token',
                'abilities' => ['*'],
            ]);

            createAccessToken($user, 'sk', [
                'name' => 'Limited Token',
                'abilities' => ['users:read'],
            ]);

            // Act
            $result = new TokenQueryConductor($user)->withAbility('users:delete')->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->name)->toBe('Admin Token');
        });

        it('finds tokens with both wildcard and specific ability', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', [
                'name' => 'Admin Token',
                'abilities' => ['*'],
            ]);

            createAccessToken($user, 'sk', [
                'name' => 'Read Token',
                'abilities' => ['users:read'],
            ]);

            // Act
            $result = new TokenQueryConductor($user)->withAbility('users:read')->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('name'))->toContain('Admin Token', 'Read Token');
        });

        it('returns empty collection when no tokens match ability', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['abilities' => ['users:read']]);

            // Act
            $result = new TokenQueryConductor($user)->withAbility('posts:delete')->get();

            // Assert
            expect($result)->toHaveCount(0);
        });
    });

    describe('orderByCreated()', function (): void {
        it('orders tokens by created_at descending by default', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'First']);
            Sleep::sleep(1);
            $token2 = createAccessToken($user, 'sk', ['name' => 'Second']);
            Sleep::sleep(1);
            $token3 = createAccessToken($user, 'sk', ['name' => 'Third']);

            // Act
            $result = new TokenQueryConductor($user)->orderByCreated()->get();

            // Assert
            expect($result)->toHaveCount(3);
            expect($result->pluck('name')->toArray())->toBe(['Third', 'Second', 'First']);
        });

        it('orders tokens by created_at ascending when specified', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'First']);
            Sleep::sleep(1);
            $token2 = createAccessToken($user, 'sk', ['name' => 'Second']);
            Sleep::sleep(1);
            $token3 = createAccessToken($user, 'sk', ['name' => 'Third']);

            // Act
            $result = new TokenQueryConductor($user)->orderByCreated('asc')->get();

            // Assert
            expect($result)->toHaveCount(3);
            expect($result->pluck('name')->toArray())->toBe(['First', 'Second', 'Third']);
        });
    });

    describe('orderByLastUsed()', function (): void {
        it('orders tokens by last_used_at descending by default', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'Token 1']);
            $token1->update(['last_used_at' => now()->subDays(3)]);

            $token2 = createAccessToken($user, 'sk', ['name' => 'Token 2']);
            $token2->update(['last_used_at' => now()->subDay()]);

            $token3 = createAccessToken($user, 'sk', ['name' => 'Token 3']);
            $token3->update(['last_used_at' => now()]);

            // Act
            $result = new TokenQueryConductor($user)->orderByLastUsed()->get();

            // Assert
            expect($result)->toHaveCount(3);
            expect($result->pluck('name')->toArray())->toBe(['Token 3', 'Token 2', 'Token 1']);
        });

        it('orders tokens by last_used_at ascending when specified', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'Token 1']);
            $token1->update(['last_used_at' => now()->subDays(3)]);

            $token2 = createAccessToken($user, 'sk', ['name' => 'Token 2']);
            $token2->update(['last_used_at' => now()->subDay()]);

            $token3 = createAccessToken($user, 'sk', ['name' => 'Token 3']);
            $token3->update(['last_used_at' => now()]);

            // Act
            $result = new TokenQueryConductor($user)->orderByLastUsed('asc')->get();

            // Assert
            expect($result)->toHaveCount(3);
            expect($result->pluck('name')->toArray())->toBe(['Token 1', 'Token 2', 'Token 3']);
        });

        it('handles tokens with null last_used_at', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'Never Used']);

            $token2 = createAccessToken($user, 'sk', ['name' => 'Recently Used']);
            $token2->update(['last_used_at' => now()]);

            // Act
            $result = new TokenQueryConductor($user)->orderByLastUsed()->get();

            // Assert
            expect($result)->toHaveCount(2);
        });
    });

    describe('limit()', function (): void {
        it('limits the number of results', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Token 1']);
            createAccessToken($user, 'sk', ['name' => 'Token 2']);
            createAccessToken($user, 'sk', ['name' => 'Token 3']);
            createAccessToken($user, 'sk', ['name' => 'Token 4']);
            createAccessToken($user, 'sk', ['name' => 'Token 5']);

            // Act
            $result = new TokenQueryConductor($user)->limit(3)->get();

            // Assert
            expect($result)->toHaveCount(3);
        });

        it('returns all tokens when limit is greater than count', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Token 1']);
            createAccessToken($user, 'sk', ['name' => 'Token 2']);

            // Act
            $result = new TokenQueryConductor($user)->limit(10)->get();

            // Assert
            expect($result)->toHaveCount(2);
        });

        it('works with other filters', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Secret 1']);
            createAccessToken($user, 'sk', ['name' => 'Secret 2']);
            createAccessToken($user, 'sk', ['name' => 'Secret 3']);
            createAccessToken($user, 'pk', ['name' => 'Publishable 1']);

            // Act
            $result = new TokenQueryConductor($user)->type('sk')->limit(2)->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('type')->unique()->first())->toBe('sk');
        });
    });

    describe('get()', function (): void {
        it('returns collection of tokens', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Token 1']);
            createAccessToken($user, 'sk', ['name' => 'Token 2']);

            // Act
            $result = new TokenQueryConductor($user)->get();

            // Assert
            expect($result)->toBeInstanceOf(Collection::class);
            expect($result)->toHaveCount(2);
            expect($result->first())->toBeInstanceOf(AccessToken::class);
        });

        it('returns empty collection when no tokens exist', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = new TokenQueryConductor($user)->get();

            // Assert
            expect($result)->toBeInstanceOf(Collection::class);
            expect($result)->toHaveCount(0);
        });
    });

    describe('first()', function (): void {
        it('returns first token', function (): void {
            // Arrange
            $user = createUser();
            $token1 = createAccessToken($user, 'sk', ['name' => 'First Token']);
            createAccessToken($user, 'sk', ['name' => 'Second Token']);

            // Act
            $result = new TokenQueryConductor($user)->first();

            // Assert
            expect($result)->toBeInstanceOf(AccessToken::class);
            expect($result->id)->toBe($token1->id);
        });

        it('returns null when no tokens exist', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = new TokenQueryConductor($user)->first();

            // Assert
            expect($result)->toBeNull();
        });

        it('works with filters', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Secret Key']);
            $publishableToken = createAccessToken($user, 'pk', ['name' => 'Publishable Key']);

            // Act
            $result = new TokenQueryConductor($user)->type('pk')->first();

            // Assert
            expect($result)->not->toBeNull();
            expect($result->id)->toBe($publishableToken->id);
        });
    });

    describe('count()', function (): void {
        it('returns count of tokens', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Token 1']);
            createAccessToken($user, 'sk', ['name' => 'Token 2']);
            createAccessToken($user, 'sk', ['name' => 'Token 3']);

            // Act
            $result = new TokenQueryConductor($user)->count();

            // Assert
            expect($result)->toBe(3);
        });

        it('returns zero when no tokens exist', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = new TokenQueryConductor($user)->count();

            // Assert
            expect($result)->toBe(0);
        });

        it('works with filters', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Secret 1']);
            createAccessToken($user, 'sk', ['name' => 'Secret 2']);
            createAccessToken($user, 'pk', ['name' => 'Publishable']);

            // Act
            $result = new TokenQueryConductor($user)->type('sk')->count();

            // Assert
            expect($result)->toBe(2);
        });
    });

    describe('exists()', function (): void {
        it('returns true when tokens exist', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Test Token']);

            // Act
            $result = new TokenQueryConductor($user)->exists();

            // Assert
            expect($result)->toBeTrue();
        });

        it('returns false when no tokens exist', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = new TokenQueryConductor($user)->exists();

            // Assert
            expect($result)->toBeFalse();
        });

        it('works with filters', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Secret Key']);

            // Act
            $existsSk = new TokenQueryConductor($user)->type('sk')->exists();
            $existsPk = new TokenQueryConductor($user)->type('pk')->exists();

            // Assert
            expect($existsSk)->toBeTrue();
            expect($existsPk)->toBeFalse();
        });
    });

    describe('toQuery()', function (): void {
        it('returns Builder instance', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = new TokenQueryConductor($user)->toQuery();

            // Assert
            expect($result)->toBeInstanceOf(Builder::class);
        });

        it('allows custom query modifications', function (): void {
            // Arrange
            $user = createUser();
            createAccessToken($user, 'sk', ['name' => 'Alpha Token']);
            createAccessToken($user, 'sk', ['name' => 'Beta Token']);
            createAccessToken($user, 'sk', ['name' => 'Gamma Token']);

            // Act
            $result = new TokenQueryConductor($user)
                ->type('sk')
                ->toQuery()
                ->where('name', 'like', '%Beta%')
                ->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->name)->toBe('Beta Token');
        });
    });

    describe('method chaining', function (): void {
        it('chains multiple filter methods', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', [
                'name' => 'Production Secret',
                'environment' => 'production',
            ]);

            createAccessToken($user, 'pk', [
                'name' => 'Production Publishable',
                'environment' => 'production',
            ]);

            createAccessToken($user, 'sk', [
                'name' => 'Staging Secret',
                'environment' => 'staging',
            ]);

            // Act
            $result = new TokenQueryConductor($user)
                ->type('sk')
                ->environment('production')
                ->get();

            // Assert
            expect($result)->toHaveCount(1);
            expect($result->first()->name)->toBe('Production Secret');
        });

        it('chains filter and ordering methods', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'Oldest']);
            Sleep::sleep(1);
            $token2 = createAccessToken($user, 'sk', ['name' => 'Middle']);
            Sleep::sleep(1);
            $token3 = createAccessToken($user, 'sk', ['name' => 'Newest']);

            createAccessToken($user, 'pk', ['name' => 'Not Secret']);

            // Act
            $result = new TokenQueryConductor($user)
                ->type('sk')
                ->orderByCreated('asc')
                ->get();

            // Assert
            expect($result)->toHaveCount(3);
            expect($result->pluck('name')->toArray())->toBe(['Oldest', 'Middle', 'Newest']);
        });

        it('chains filter, ordering, and limit methods', function (): void {
            // Arrange
            $user = createUser();

            createAccessToken($user, 'sk', ['name' => 'Valid 1']);
            createAccessToken($user, 'sk', ['name' => 'Valid 2']);
            createAccessToken($user, 'sk', ['name' => 'Valid 3']);

            $expired = Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired');

            // Act
            $result = new TokenQueryConductor($user)
                ->valid()
                ->orderByCreated('desc')
                ->limit(2)
                ->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('name'))->not->toContain('Expired');
        });

        it('chains group and ability filters', function (): void {
            // Arrange
            $user = createUser();

            $group = Bearer::for($user)
                ->abilities(['users:read'])
                ->issueGroup(['sk', 'pk'], 'Read Only Group');

            createAccessToken($user, 'sk', ['abilities' => ['users:write']]);

            // Act
            $result = new TokenQueryConductor($user)
                ->group($group->id)
                ->withAbility('users:read')
                ->get();

            // Assert
            expect($result)->toHaveCount(2);
            expect($result->pluck('group_id')->unique()->first())->toBe($group->id);
        });
    });

    describe('edge cases', function (): void {
        it('handles empty user with no tokens', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $getResult = new TokenQueryConductor($user)->get();
            $firstResult = new TokenQueryConductor($user)->first();
            $countResult = new TokenQueryConductor($user)->count();
            $existsResult = new TokenQueryConductor($user)->exists();

            // Assert
            expect($getResult)->toHaveCount(0);
            expect($firstResult)->toBeNull();
            expect($countResult)->toBe(0);
            expect($existsResult)->toBeFalse();
        });

        it('handles user with only expired tokens', function (): void {
            // Arrange
            $user = createUser();

            Bearer::for($user)
                ->expiresAt(now()->subDay())
                ->issue('sk', 'Expired 1');

            Bearer::for($user)
                ->expiresAt(now()->subHour())
                ->issue('sk', 'Expired 2');

            // Act
            $valid = new TokenQueryConductor($user)->valid()->count();
            $expired = new TokenQueryConductor($user)->expired()->count();

            // Assert
            expect($valid)->toBe(0);
            expect($expired)->toBe(2);
        });

        it('handles user with only revoked tokens', function (): void {
            // Arrange
            $user = createUser();

            $token1 = createAccessToken($user, 'sk', ['name' => 'Revoked 1']);
            $token1->revoke();

            $token2 = createAccessToken($user, 'sk', ['name' => 'Revoked 2']);
            $token2->revoke();

            // Act
            $valid = new TokenQueryConductor($user)->valid()->count();
            $revoked = new TokenQueryConductor($user)->revoked()->count();

            // Assert
            expect($valid)->toBe(0);
            expect($revoked)->toBe(2);
        });

        it('isolates tokens between different users', function (): void {
            // Arrange
            $user1 = createUser(['email' => 'user1@example.com']);
            $user2 = createUser(['email' => 'user2@example.com']);

            createAccessToken($user1, 'sk', ['name' => 'User 1 Token']);
            createAccessToken($user2, 'sk', ['name' => 'User 2 Token']);

            // Act
            $user1Tokens = new TokenQueryConductor($user1)->get();
            $user2Tokens = new TokenQueryConductor($user2)->get();

            // Assert
            expect($user1Tokens)->toHaveCount(1);
            expect($user1Tokens->first()->name)->toBe('User 1 Token');
            expect($user2Tokens)->toHaveCount(1);
            expect($user2Tokens->first()->name)->toBe('User 2 Token');
        });
    });
});
