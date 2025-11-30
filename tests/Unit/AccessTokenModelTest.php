<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Facades\Bearer;
use Tests\Fixtures\User;

describe('AccessToken Model', function (): void {
    describe('Happy Path', function (): void {
        test('findToken() locates token by plain text hash when no prefix', function (): void {
            // Arrange
            $user = createUser();
            $newToken = Bearer::for($user)->issue('sk', 'Test Token');
            $plainToken = $newToken->plainTextToken;

            // Act
            $found = Bearer::findToken($plainToken);

            // Assert
            expect($found)->not->toBeNull();
            expect($found->id)->toBe($newToken->accessToken->id);
        });

        test('findToken() locates token by prefixed token with id', function (): void {
            // Arrange
            $user = createUser();
            $newToken = Bearer::for($user)->issue('sk', 'Test Token');

            // Create id|plaintext format
            $prefixedToken = $newToken->accessToken->id.'|'.$newToken->plainTextToken;

            // Act
            $found = Bearer::findToken($prefixedToken);

            // Assert
            expect($found)->not->toBeNull();
            expect($found->id)->toBe($newToken->accessToken->id);
        });

        test('sibling() returns sibling token of requested type', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk', 'rk'],
                name: 'Test Group',
            );

            $secretKey = $group->secretKey();

            // Act
            $publishableKey = $secretKey->sibling('pk');
            $restrictedKey = $secretKey->sibling('rk');

            // Assert
            expect($publishableKey)->not->toBeNull();
            expect($publishableKey->type)->toBe('pk');
            expect($publishableKey->group_id)->toBe($secretKey->group_id);

            expect($restrictedKey)->not->toBeNull();
            expect($restrictedKey->type)->toBe('rk');
            expect($restrictedKey->group_id)->toBe($secretKey->group_id);
        });
    });

    describe('Sad Path', function (): void {
        test('findToken() returns null when prefixed token id does not exist', function (): void {
            // Arrange
            $user = createUser();
            $newToken = Bearer::for($user)->issue('sk', 'Test Token');

            // Create id|plaintext with non-existent ID
            $nonExistentId = 999_999;
            $invalidToken = sprintf('%d|%s', $nonExistentId, $newToken->plainTextToken);

            // Act
            $found = Bearer::findToken($invalidToken);

            // Assert
            expect($found)->toBeNull();
        });

        test('findToken() returns null when prefixed token verification fails', function (): void {
            // Arrange
            $user = createUser();
            $newToken = Bearer::for($user)->issue('sk', 'Test Token');

            // Create id|plaintext with valid id but invalid plaintext
            $invalidToken = $newToken->accessToken->id.'|invalid_plain_text_token';

            // Act
            $found = Bearer::findToken($invalidToken);

            // Assert
            expect($found)->toBeNull();
        });

        test('sibling() returns null when token has no group_id', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user, 'sk', ['name' => 'Standalone Token']);

            // Ensure token has no group_id
            expect($token->group_id)->toBeNull();

            // Act
            $sibling = $token->sibling('pk');

            // Assert
            expect($sibling)->toBeNull();
        });
    });

    describe('Edge Cases', function (): void {
        test('sibling() does not return itself when searching for same type', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Test Group',
            );

            $secretKey = $group->secretKey();

            // Act
            $sibling = $secretKey->sibling('sk');

            // Assert
            expect($sibling)->toBeNull();
        });

        test('sibling() returns null when requested type does not exist in group', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Test Group',
            );

            $secretKey = $group->secretKey();

            // Act
            $sibling = $secretKey->sibling('rk');

            // Assert
            expect($sibling)->toBeNull();
        });

        test('findToken() handles plain token without pipe separator', function (): void {
            // Arrange
            $user = createUser();
            $newToken = Bearer::for($user)->issue('sk', 'Test Token');

            // Act - Use the plain token directly (no id| prefix)
            $found = Bearer::findToken($newToken->plainTextToken);

            // Assert
            expect($found)->not->toBeNull();
            expect($found->id)->toBe($newToken->accessToken->id);
        });
    });
});

describe('AccessTokenGroup Model', function (): void {
    describe('Happy Path', function (): void {
        test('owner() relationship returns the owning model', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Test Group',
            );

            // Refresh to load relationships
            $group->refresh();

            // Act
            $owner = $group->owner;

            // Assert
            expect($owner)->not->toBeNull();
            expect($owner->id)->toBe($user->id);
            expect($owner)->toBeInstanceOf(User::class);
        });

        test('restrictedKey() returns restricted key token from group', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk', 'rk'],
                name: 'Full Group',
            );

            // Act
            $restrictedKey = $group->restrictedKey();

            // Assert
            expect($restrictedKey)->not->toBeNull();
            expect($restrictedKey->type)->toBe('rk');
            expect($restrictedKey->group_id)->toBe($group->id);
        });

        test('secretKey() returns secret key token from group', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Test Group',
            );

            // Act
            $secretKey = $group->secretKey();

            // Assert
            expect($secretKey)->not->toBeNull();
            expect($secretKey->type)->toBe('sk');
            expect($secretKey->group_id)->toBe($group->id);
        });

        test('publishableKey() returns publishable key token from group', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Test Group',
            );

            // Act
            $publishableKey = $group->publishableKey();

            // Assert
            expect($publishableKey)->not->toBeNull();
            expect($publishableKey->type)->toBe('pk');
            expect($publishableKey->group_id)->toBe($group->id);
        });
    });

    describe('Edge Cases', function (): void {
        test('restrictedKey() returns null when group has no restricted key', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'pk'],
                name: 'Partial Group',
            );

            // Act
            $restrictedKey = $group->restrictedKey();

            // Assert
            expect($restrictedKey)->toBeNull();
        });

        test('secretKey() returns null when group has no secret key', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['pk', 'rk'],
                name: 'No Secret Key Group',
            );

            // Act
            $secretKey = $group->secretKey();

            // Assert
            expect($secretKey)->toBeNull();
        });

        test('publishableKey() returns null when group has no publishable key', function (): void {
            // Arrange
            $user = createUser();
            $group = Bearer::for($user)->issueGroup(
                types: ['sk', 'rk'],
                name: 'No Publishable Key Group',
            );

            // Act
            $publishableKey = $group->publishableKey();

            // Assert
            expect($publishableKey)->toBeNull();
        });
    });
});
