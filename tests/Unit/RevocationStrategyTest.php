<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\RevocationStrategies\CascadeStrategy;
use Cline\Bearer\RevocationStrategies\NoneStrategy;
use Cline\Bearer\RevocationStrategies\PartialCascadeStrategy;
use Cline\Bearer\RevocationStrategies\TimedStrategy;
use Illuminate\Support\Facades\Date;
use Tests\Fixtures\User;

describe('CascadeStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('revokes all tokens in group when token is part of a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'sk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $token3 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-3',
                'prefix' => 'pk',
                'token' => 'test-token-3',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->not->toBeNull();
            expect($token3->fresh()->revoked_at)->not->toBeNull();
        });

        test('revokes only single token when not part of a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'standalone-token',
                'prefix' => 'sk',
                'token' => 'test-token-standalone',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'other-token',
                'prefix' => 'sk',
                'token' => 'test-token-other',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->toBeNull();
        });

        test('getAffectedTokens returns all group tokens when token is in a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'rk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token1);

            // Assert
            expect($affectedTokens)->toHaveCount(2);
            expect($affectedTokens->pluck('id')->toArray())->toContain($token1->id, $token2->id);
        });

        test('getAffectedTokens returns single token when not in a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'standalone-token',
                'prefix' => 'sk',
                'token' => 'test-token-standalone',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token);

            // Assert
            expect($affectedTokens)->toHaveCount(1);
            expect($affectedTokens->first()->id)->toBe($token->id);
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty group gracefully', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'empty-group',
            ]);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'single-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $strategy->revoke($token);

            // Assert
            expect($token->fresh()->revoked_at)->not->toBeNull();
        });

        test('revocation timestamp is set to current time', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new CascadeStrategy();

            // Act
            $strategy->revoke($token);

            // Assert
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe('2024-11-26 12:00:00');

            Date::setTestNow();
        });
    });
});

describe('NoneStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('revokes only the specified token', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'sk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $strategy = new NoneStrategy();

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->toBeNull();
        });

        test('does not affect tokens in same group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'sk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $strategy = new NoneStrategy();

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->toBeNull();
        });

        test('getAffectedTokens returns single token collection', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new NoneStrategy();

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token);

            // Assert
            expect($affectedTokens)->toHaveCount(1);
            expect($affectedTokens->first()->id)->toBe($token->id);
        });

        test('getAffectedTokens returns single token even when token is in a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'sk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $strategy = new NoneStrategy();

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token1);

            // Assert
            expect($affectedTokens)->toHaveCount(1);
            expect($affectedTokens->first()->id)->toBe($token1->id);
        });
    });

    describe('Edge Cases', function (): void {
        test('revocation timestamp is set to current time', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 15:30:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new NoneStrategy();

            // Act
            $strategy->revoke($token);

            // Assert
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe('2024-11-26 15:30:00');

            Date::setTestNow();
        });
    });
});

describe('PartialCascadeStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('revokes only default prefix tokens in group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $skToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'secret-token',
                'prefix' => 'sk',
                'token' => 'test-token-sk',
                'abilities' => ['*'],
            ]);

            $rkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'restricted-token',
                'prefix' => 'rk',
                'token' => 'test-token-rk',
                'abilities' => ['*'],
            ]);

            $pkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'publishable-token',
                'prefix' => 'pk',
                'token' => 'test-token-pk',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $strategy->revoke($skToken);

            // Assert
            expect($skToken->fresh()->revoked_at)->not->toBeNull();
            expect($rkToken->fresh()->revoked_at)->not->toBeNull();
            expect($pkToken->fresh()->revoked_at)->toBeNull();
        });

        test('revokes only custom prefix tokens in group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $skToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'secret-token',
                'prefix' => 'sk',
                'token' => 'test-token-sk',
                'abilities' => ['*'],
            ]);

            $pkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'publishable-token',
                'prefix' => 'pk',
                'token' => 'test-token-pk',
                'abilities' => ['*'],
            ]);

            $customToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'custom-token',
                'prefix' => 'custom',
                'token' => 'test-token-custom',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['pk', 'custom']);

            // Act
            $strategy->revoke($pkToken);

            // Assert
            expect($skToken->fresh()->revoked_at)->toBeNull();
            expect($pkToken->fresh()->revoked_at)->not->toBeNull();
            expect($customToken->fresh()->revoked_at)->not->toBeNull();
        });

        test('revokes single token when not in a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'standalone-token',
                'prefix' => 'sk',
                'token' => 'test-token-standalone',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'other-token',
                'prefix' => 'sk',
                'token' => 'test-token-other',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->toBeNull();
        });

        test('getAffectedTokens returns only matching prefix tokens in group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $skToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'secret-token',
                'prefix' => 'sk',
                'token' => 'test-token-sk',
                'abilities' => ['*'],
            ]);

            $rkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'restricted-token',
                'prefix' => 'rk',
                'token' => 'test-token-rk',
                'abilities' => ['*'],
            ]);

            $pkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'publishable-token',
                'prefix' => 'pk',
                'token' => 'test-token-pk',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $affectedTokens = $strategy->getAffectedTokens($skToken);

            // Assert
            expect($affectedTokens)->toHaveCount(2);
            expect($affectedTokens->pluck('id')->toArray())->toContain($skToken->id, $rkToken->id);
            expect($affectedTokens->pluck('id')->toArray())->not->toContain($pkToken->id);
        });

        test('getAffectedTokens returns single token when not in a group', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'standalone-token',
                'prefix' => 'sk',
                'token' => 'test-token-standalone',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token);

            // Assert
            expect($affectedTokens)->toHaveCount(1);
            expect($affectedTokens->first()->id)->toBe($token->id);
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty prefixes array', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy([]);

            // Act
            $strategy->revoke($token);

            // Assert
            expect($token->fresh()->revoked_at)->toBeNull();
        });

        test('handles group with no matching prefix tokens', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $pkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'publishable-token',
                'prefix' => 'pk',
                'token' => 'test-token-pk',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $affectedTokens = $strategy->getAffectedTokens($pkToken);

            // Assert
            expect($affectedTokens)->toHaveCount(0);
        });

        test('uses default prefixes when none specified', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $skToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'secret-token',
                'prefix' => 'sk',
                'token' => 'test-token-sk',
                'abilities' => ['*'],
            ]);

            $rkToken = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'restricted-token',
                'prefix' => 'rk',
                'token' => 'test-token-rk',
                'abilities' => ['*'],
            ]);

            $strategy = new PartialCascadeStrategy(['sk', 'rk']);

            // Act
            $affectedTokens = $strategy->getAffectedTokens($skToken);

            // Assert
            expect($affectedTokens)->toHaveCount(2);
            expect($affectedTokens->pluck('prefix')->toArray())->toContain('sk', 'rk');
        });
    });
});

describe('TimedStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('schedules revocation with default 60 minute delay', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(60);

            // Act
            $strategy->revoke($token);

            // Assert
            $expectedTime = $now->copy()->addMinutes(60);
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe($expectedTime->toDateTimeString());

            Date::setTestNow();
        });

        test('schedules revocation with custom delay', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(120);

            // Act
            $strategy->revoke($token);

            // Assert
            $expectedTime = $now->copy()->addMinutes(120);
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe($expectedTime->toDateTimeString());

            Date::setTestNow();
        });

        test('getAffectedTokens returns single token collection', function (): void {
            // Arrange
            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(60);

            // Act
            $affectedTokens = $strategy->getAffectedTokens($token);

            // Assert
            expect($affectedTokens)->toHaveCount(1);
            expect($affectedTokens->first()->id)->toBe($token->id);
        });

        test('does not affect tokens in same group', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $group = AccessTokenGroup::query()->forceCreate([
                'owner_type' => User::class,
                'owner_id' => $user->id,
                'name' => 'test-group',
            ]);

            $token1 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-1',
                'prefix' => 'sk',
                'token' => 'test-token-1',
                'abilities' => ['*'],
            ]);

            $token2 = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'group_id' => $group->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'token-2',
                'prefix' => 'sk',
                'token' => 'test-token-2',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(60);

            // Act
            $strategy->revoke($token1);

            // Assert
            expect($token1->fresh()->revoked_at)->not->toBeNull();
            expect($token2->fresh()->revoked_at)->toBeNull();

            Date::setTestNow();
        });
    });

    describe('Edge Cases', function (): void {
        test('handles zero minute delay', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(0);

            // Act
            $strategy->revoke($token);

            // Assert
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe($now->toDateTimeString());

            Date::setTestNow();
        });

        test('handles large delay values', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(10_080); // 1 week

            // Act
            $strategy->revoke($token);

            // Assert
            $expectedTime = $now->copy()->addMinutes(10_080);
            expect($token->fresh()->revoked_at->toDateTimeString())->toBe($expectedTime->toDateTimeString());

            Date::setTestNow();
        });

        test('maintains scheduled time across multiple calls', function (): void {
            // Arrange
            $now = Date::parse('2024-11-26 12:00:00');
            Date::setTestNow($now);

            $user = User::query()->create(['name' => 'Test User', 'email' => 'test@example.com', 'password' => 'password']);

            $token = AccessToken::query()->forceCreate([
                'tokenable_type' => User::class,
                'tokenable_id' => $user->id,
                'type' => 'api',
                'environment' => 'test',
                'name' => 'test-token',
                'prefix' => 'sk',
                'token' => 'test-token',
                'abilities' => ['*'],
            ]);

            $strategy = new TimedStrategy(30);

            // Act
            $strategy->revoke($token);

            $firstRevocationTime = $token->fresh()->revoked_at;

            Date::setTestNow($now->copy()->addMinutes(10));
            $strategy->revoke($token);
            $secondRevocationTime = $token->fresh()->revoked_at;

            // Assert
            expect($firstRevocationTime->toDateTimeString())->toBe($now->copy()->addMinutes(30)->toDateTimeString());
            expect($secondRevocationTime->toDateTimeString())->toBe($now->copy()->addMinutes(40)->toDateTimeString());

            Date::setTestNow();
        });
    });
});
