<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Tests\Fixtures\User;

describe('HasApiTokens Trait', function (): void {
    describe('Token Group Creation', function (): void {
        it('creates token group with multiple types', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk', 'rk'],
                name: 'Test Group',
            );

            // Assert
            expect($group)->toBeInstanceOf(AccessTokenGroup::class);
            expect($group->name)->toBe('Test Group');
            expect($group->tokens)->toHaveCount(3);
            expect($group->secretKey())->not->toBeNull();
            expect($group->publishableKey())->not->toBeNull();
            expect($group->restrictedKey())->not->toBeNull();
        });

        it('creates token group with abilities', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'API Group',
                abilities: ['users:read', 'posts:write'],
            );

            // Assert
            expect($group->secretKey()->abilities)->toBe(['users:read', 'posts:write']);
            expect($group->publishableKey()->abilities)->toBe(['users:read', 'posts:write']);
        });

        it('creates token group with environment', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'Production Group',
                environment: 'production',
            );

            // Assert
            expect($group->secretKey()->environment)->toBe('production');
            expect($group->publishableKey()->environment)->toBe('production');
        });

        it('creates token group with metadata', function (): void {
            // Arrange
            $user = createUser();
            $metadata = ['app' => 'mobile', 'version' => '2.0'];

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'Mobile App',
                metadata: $metadata,
            );

            // Assert
            expect($group->secretKey()->metadata)->toBe($metadata);
            expect($group->publishableKey()->metadata)->toBe($metadata);
        });

        it('creates token group with all parameters', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk', 'rk'],
                name: 'Complete Group',
                abilities: ['*'],
                environment: 'staging',
                metadata: ['client_id' => 'test-123'],
            );

            // Assert
            expect($group)->toBeInstanceOf(AccessTokenGroup::class);
            expect($group->name)->toBe('Complete Group');
            expect($group->tokens)->toHaveCount(3);

            $secretKey = $group->secretKey();
            expect($secretKey->abilities)->toBe(['*']);
            expect($secretKey->environment)->toBe('staging');
            expect($secretKey->metadata)->toBe(['client_id' => 'test-123']);
        });
    });

    describe('Token Groups Relationship', function (): void {
        it('returns MorphMany relationship', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $relationship = $user->tokenGroups();

            // Assert
            expect($relationship)->toBeInstanceOf(MorphMany::class);
        });

        it('retrieves all token groups for user', function (): void {
            // Arrange
            $user = createUser();
            $user->createAccessTokenGroup(['sk', 'pk'], 'Group 1');
            $user->createAccessTokenGroup(['sk', 'rk'], 'Group 2');

            // Act
            $groups = $user->tokenGroups()->get();

            // Assert
            expect($groups)->toHaveCount(2);
            expect($groups->pluck('name')->toArray())->toBe(['Group 1', 'Group 2']);
        });

        it('filters token groups by name', function (): void {
            // Arrange
            $user = createUser();
            $user->createAccessTokenGroup(['sk', 'pk'], 'Production');
            $user->createAccessTokenGroup(['sk', 'rk'], 'Development');

            // Act
            $productionGroup = $user->tokenGroups()->where('name', 'Production')->first();

            // Assert
            expect($productionGroup)->not->toBeNull();
            expect($productionGroup->name)->toBe('Production');
        });
    });

    describe('Model Deletion Cascade', function (): void {
        it('deletes tokens when user is deleted', function (): void {
            // Arrange
            $user = createUser();
            $token1 = createToken($user, 'sk', ['name' => 'Token 1']);
            $token2 = createToken($user, 'sk', ['name' => 'Token 2']);

            $tokenIds = [$token1->id, $token2->id];

            // Act
            $user->delete();

            // Assert
            foreach ($tokenIds as $tokenId) {
                expect(AccessToken::query()->find($tokenId))->toBeNull();
            }
        });

        it('deletes token groups when user is deleted', function (): void {
            // Arrange
            $user = createUser();
            $group1 = $user->createAccessTokenGroup(['sk', 'pk'], 'Group 1');
            $group2 = $user->createAccessTokenGroup(['sk', 'rk'], 'Group 2');

            $groupIds = [$group1->id, $group2->id];

            // Act
            $user->delete();

            // Assert
            foreach ($groupIds as $groupId) {
                expect(AccessTokenGroup::query()->find($groupId))->toBeNull();
            }
        });

        it('cascade deletes both tokens and token groups', function (): void {
            // Arrange
            $user = createUser();

            // Create individual tokens
            $token = createToken($user, 'sk', ['name' => 'Standalone Token']);

            // Create token groups (with their tokens)
            $group = $user->createAccessTokenGroup(['sk', 'pk'], 'Test Group');

            $tokenId = $token->id;
            $groupId = $group->id;
            $groupTokenIds = $group->tokens->pluck('id')->toArray();

            // Act
            $user->delete();

            // Assert
            expect(AccessToken::query()->find($tokenId))->toBeNull();
            expect(AccessTokenGroup::query()->find($groupId))->toBeNull();

            foreach ($groupTokenIds as $groupTokenId) {
                expect(AccessToken::query()->find($groupTokenId))->toBeNull();
            }
        });

        it('does not affect other users tokens on deletion', function (): void {
            // Arrange
            $user1 = createUser(['email' => 'user1@example.com']);
            $user2 = createUser(['email' => 'user2@example.com']);

            $token1 = createToken($user1);
            $token2 = createToken($user2);

            // Act
            $user1->delete();

            // Assert
            expect(AccessToken::query()->find($token1->id))->toBeNull();
            expect(AccessToken::query()->find($token2->id))->not->toBeNull();
        });
    });

    describe('Token Checking Without Current Token', function (): void {
        it('tokenIs returns false when no AccessToken set', function (): void {
            // Arrange
            $user = createUser();

            // Act & Assert
            expect($user->tokenIs('sk'))->toBeFalse();
            expect($user->tokenIs('pk'))->toBeFalse();
            expect($user->tokenIs('rk'))->toBeFalse();
        });

        it('tokenEnvironment returns null when no AccessToken set', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $environment = $user->tokenEnvironment();

            // Assert
            expect($environment)->toBeNull();
        });

        it('tokenType returns null when no AccessToken set', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $type = $user->tokenType();

            // Assert
            expect($type)->toBeNull();
        });
    });

    describe('Token Checking With Current Token', function (): void {
        it('tokenIs returns true for matching token type', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user, 'sk');
            $user->withAccessToken($token);

            // Act & Assert
            expect($user->tokenIs('sk'))->toBeTrue();
            expect($user->tokenIs('pk'))->toBeFalse();
        });

        it('tokenEnvironment returns current token environment', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user, 'sk', ['environment' => 'production']);
            $user->withAccessToken($token);

            // Act
            $environment = $user->tokenEnvironment();

            // Assert
            expect($environment)->toBe('production');
        });

        it('tokenType returns current token type', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user, 'pk');
            $user->withAccessToken($token);

            // Act
            $type = $user->tokenType();

            // Assert
            expect($type)->toBe('pk');
        });

        it('handles different token types correctly', function (): void {
            // Arrange
            $user = createUser();

            // Act & Assert - Secret Key
            $secretToken = createToken($user, 'sk');
            $user->withAccessToken($secretToken);
            expect($user->tokenIs('sk'))->toBeTrue();
            expect($user->tokenType())->toBe('sk');

            // Act & Assert - Publishable Key
            $publishableToken = createToken($user, 'pk');
            $user->withAccessToken($publishableToken);
            expect($user->tokenIs('pk'))->toBeTrue();
            expect($user->tokenType())->toBe('pk');

            // Act & Assert - Restricted Key
            $restrictedToken = createToken($user, 'rk');
            $user->withAccessToken($restrictedToken);
            expect($user->tokenIs('rk'))->toBeTrue();
            expect($user->tokenType())->toBe('rk');
        });

        it('handles different environments correctly', function (): void {
            // Arrange
            $user = createUser();

            // Act & Assert - Production
            $prodToken = createToken($user, 'sk', ['environment' => 'production']);
            $user->withAccessToken($prodToken);
            expect($user->tokenEnvironment())->toBe('production');

            // Act & Assert - Development
            $devToken = createToken($user, 'sk', ['environment' => 'development']);
            $user->withAccessToken($devToken);
            expect($user->tokenEnvironment())->toBe('development');

            // Act & Assert - Staging
            $stagingToken = createToken($user, 'sk', ['environment' => 'staging']);
            $user->withAccessToken($stagingToken);
            expect($user->tokenEnvironment())->toBe('staging');
        });
    });

    describe('Edge Cases', function (): void {
        it('creates token group with single type', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk'],
                name: 'Single Token Group',
            );

            // Assert
            expect($group->tokens)->toHaveCount(1);
            expect($group->secretKey())->not->toBeNull();
        });

        it('creates token group with empty abilities array', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'No Abilities',
                abilities: [],
            );

            // Assert
            expect($group->secretKey()->abilities)->toBe([]);
            expect($group->publishableKey()->abilities)->toBe([]);
        });

        it('creates token group with null environment', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'Null Environment',
                environment: null,
            );

            // Assert - when null is passed, Bearer uses its default environment
            expect($group->secretKey())->not->toBeNull();
            expect($group->publishableKey())->not->toBeNull();
        });

        it('creates token group with empty metadata', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $group = $user->createAccessTokenGroup(
                types: ['sk', 'pk'],
                name: 'Empty Metadata',
                metadata: [],
            );

            // Assert
            expect($group->secretKey()->metadata)->toBe([]);
            expect($group->publishableKey()->metadata)->toBe([]);
        });

        it('tokenIs checks exact type match', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user, 'sk');
            $user->withAccessToken($token);

            // Act & Assert
            expect($user->tokenIs('sk'))->toBeTrue();
            expect($user->tokenIs('SK'))->toBeFalse();
            expect($user->tokenIs('secret_key'))->toBeFalse();
            expect($user->tokenIs('s'))->toBeFalse();
        });

        it('handles user with no tokens', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokens = $user->tokens()->get();
            $groups = $user->tokenGroups()->get();

            // Assert
            expect($tokens)->toBeEmpty();
            expect($groups)->toBeEmpty();
        });

        it('deletes user with no tokens or groups', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = $user->delete();

            // Assert
            expect($result)->toBeTrue();
            expect(User::query()->find($user->id))->toBeNull();
        });
    });
});
