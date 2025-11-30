<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Testing\TestingToken;
use Cline\Bearer\TransientToken;

describe('TransientToken', function (): void {
    describe('Happy Path', function (): void {
        test('can() always returns true for any ability', function (): void {
            // Arrange
            $token = new TransientToken();

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:posts'))->toBeTrue();
            expect($token->can('delete:posts'))->toBeTrue();
            expect($token->can('admin'))->toBeTrue();
            expect($token->can('*'))->toBeTrue();
        });

        test('cant() always returns false for any ability', function (): void {
            // Arrange
            $token = new TransientToken();

            // Act & Assert
            expect($token->cant('read:posts'))->toBeFalse();
            expect($token->cant('write:posts'))->toBeFalse();
            expect($token->cant('delete:posts'))->toBeFalse();
            expect($token->cant('admin'))->toBeFalse();
            expect($token->cant('*'))->toBeFalse();
        });

        test('can() returns true for empty string ability', function (): void {
            // Arrange
            $token = new TransientToken();

            // Act
            $result = $token->can('');

            // Assert
            expect($result)->toBeTrue();
        });

        test('cant() returns false for empty string ability', function (): void {
            // Arrange
            $token = new TransientToken();

            // Act
            $result = $token->cant('');

            // Assert
            expect($result)->toBeFalse();
        });
    });
});

describe('TestingToken', function (): void {
    describe('Happy Path', function (): void {
        test('constructor with default abilities contains wildcard', function (): void {
            // Arrange & Act
            $token = new TestingToken();

            // Assert
            expect($token->can('any:ability'))->toBeTrue();
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('*'))->toBeTrue();
        });

        test('constructor with default abilities and null type', function (): void {
            // Arrange & Act
            $token = new TestingToken();

            // Assert
            expect($token->type)->toBeNull();
        });

        test('constructor with custom abilities and type', function (): void {
            // Arrange
            $abilities = ['read:posts', 'write:posts'];
            $type = 'sk';

            // Act
            $token = new TestingToken($abilities, $type);

            // Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:posts'))->toBeTrue();
            expect($token->type)->toBe('sk');
        });

        test('__get with type property returns configured type', function (): void {
            // Arrange
            $token = new TestingToken(['*'], 'pk');

            // Act
            $result = $token->type;

            // Assert
            expect($result)->toBe('pk');
        });

        test('__get with unknown property returns null', function (): void {
            // Arrange
            $token = new TestingToken(['*'], 'rk');

            // Act
            $result = $token->unknown;

            // Assert
            expect($result)->toBeNull();
        });

        test('can() returns true when abilities contains wildcard', function (): void {
            // Arrange
            $token = new TestingToken(['*']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:users'))->toBeTrue();
            expect($token->can('delete:comments'))->toBeTrue();
            expect($token->can('admin'))->toBeTrue();
        });

        test('can() returns true when specific ability is in abilities array', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts', 'write:posts', 'delete:posts']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:posts'))->toBeTrue();
            expect($token->can('delete:posts'))->toBeTrue();
        });

        test('can() returns false when ability is not in abilities array and no wildcard', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts', 'write:posts']);

            // Act & Assert
            expect($token->can('delete:posts'))->toBeFalse();
            expect($token->can('admin'))->toBeFalse();
            expect($token->can('read:users'))->toBeFalse();
        });

        test('cant() returns opposite of can() for wildcard', function (): void {
            // Arrange
            $token = new TestingToken(['*']);

            // Act & Assert
            expect($token->cant('read:posts'))->toBeFalse();
            expect($token->cant('write:users'))->toBeFalse();
        });

        test('cant() returns opposite of can() for specific abilities', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts', 'write:posts']);

            // Act & Assert
            expect($token->cant('read:posts'))->toBeFalse();
            expect($token->cant('write:posts'))->toBeFalse();
            expect($token->cant('delete:posts'))->toBeTrue();
            expect($token->cant('admin'))->toBeTrue();
        });

        test('can() with empty abilities array denies all abilities', function (): void {
            // Arrange
            $token = new TestingToken([]);

            // Act & Assert
            expect($token->can('read:posts'))->toBeFalse();
            expect($token->can('*'))->toBeFalse();
            expect($token->can(''))->toBeFalse();
        });

        test('cant() with empty abilities array allows all abilities', function (): void {
            // Arrange
            $token = new TestingToken([]);

            // Act & Assert
            expect($token->cant('read:posts'))->toBeTrue();
            expect($token->cant('*'))->toBeTrue();
            expect($token->cant(''))->toBeTrue();
        });
    });

    describe('Edge Cases', function (): void {
        test('can() checks are case-sensitive', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('Read:Posts'))->toBeFalse();
            expect($token->can('READ:POSTS'))->toBeFalse();
        });

        test('handles multiple token types', function (): void {
            // Arrange
            $skToken = new TestingToken(['read:posts'], 'sk');
            $pkToken = new TestingToken(['*'], 'pk');
            $rkToken = new TestingToken(['write:posts'], 'rk');

            // Act & Assert
            expect($skToken->type)->toBe('sk');
            expect($pkToken->type)->toBe('pk');
            expect($rkToken->type)->toBe('rk');
        });

        test('handles abilities with special characters', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts', 'write:blog/posts', 'admin:*']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:blog/posts'))->toBeTrue();
            expect($token->can('admin:*'))->toBeTrue();
        });

        test('handles single ability in array', function (): void {
            // Arrange
            $token = new TestingToken(['admin']);

            // Act & Assert
            expect($token->can('admin'))->toBeTrue();
            expect($token->can('other'))->toBeFalse();
        });

        test('handles duplicate abilities in array', function (): void {
            // Arrange
            $token = new TestingToken(['read:posts', 'read:posts', 'write:posts']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:posts'))->toBeTrue();
        });

        test('wildcard takes precedence over specific abilities', function (): void {
            // Arrange
            $token = new TestingToken(['*', 'read:posts']);

            // Act & Assert
            expect($token->can('read:posts'))->toBeTrue();
            expect($token->can('write:posts'))->toBeTrue();
            expect($token->can('delete:posts'))->toBeTrue();
            expect($token->can('any:ability'))->toBeTrue();
        });
    });
});
