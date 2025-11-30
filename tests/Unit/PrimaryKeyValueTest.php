<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Enums\PrimaryKeyType;
use Cline\Bearer\Support\PrimaryKeyValue;

describe('Happy Path', function (): void {
    describe('constructor', function (): void {
        test('creates instance with Id type and null value', function (): void {
            // Arrange & Act
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::Id, null);

            // Assert
            expect($primaryKey->type)->toBe(PrimaryKeyType::Id);
            expect($primaryKey->value)->toBeNull();
        });

        test('creates instance with Uuid type and value', function (): void {
            // Arrange
            $uuidValue = '550e8400-e29b-41d4-a716-446655440000';

            // Act
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::UUID, $uuidValue);

            // Assert
            expect($primaryKey->type)->toBe(PrimaryKeyType::UUID);
            expect($primaryKey->value)->toBe($uuidValue);
        });

        test('creates instance with Ulid type and value', function (): void {
            // Arrange
            $ulidValue = '01ARZ3NDEKTSV4RRFFQ69G5FAV';

            // Act
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::ULID, $ulidValue);

            // Assert
            expect($primaryKey->type)->toBe(PrimaryKeyType::ULID);
            expect($primaryKey->value)->toBe($ulidValue);
        });
    });

    describe('isAutoIncrementing', function (): void {
        test('returns true for Id type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::Id, null);

            // Act
            $result = $primaryKey->isAutoIncrementing();

            // Assert
            expect($result)->toBeTrue();
        });

        test('returns false for Uuid type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::UUID, '550e8400-e29b-41d4-a716-446655440000');

            // Act
            $result = $primaryKey->isAutoIncrementing();

            // Assert
            expect($result)->toBeFalse();
        });

        test('returns false for Ulid type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::ULID, '01ARZ3NDEKTSV4RRFFQ69G5FAV');

            // Act
            $result = $primaryKey->isAutoIncrementing();

            // Assert
            expect($result)->toBeFalse();
        });
    });

    describe('requiresValue', function (): void {
        test('returns false for Id type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::Id, null);

            // Act
            $result = $primaryKey->requiresValue();

            // Assert
            expect($result)->toBeFalse();
        });

        test('returns true for Uuid type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::UUID, '550e8400-e29b-41d4-a716-446655440000');

            // Act
            $result = $primaryKey->requiresValue();

            // Assert
            expect($result)->toBeTrue();
        });

        test('returns true for Ulid type', function (): void {
            // Arrange
            $primaryKey = new PrimaryKeyValue(PrimaryKeyType::ULID, '01ARZ3NDEKTSV4RRFFQ69G5FAV');

            // Act
            $result = $primaryKey->requiresValue();

            // Assert
            expect($result)->toBeTrue();
        });
    });
});

describe('Edge Cases', function (): void {
    test('handles empty string value for Uuid type', function (): void {
        // Arrange
        $primaryKey = new PrimaryKeyValue(PrimaryKeyType::UUID, '');

        // Act & Assert
        expect($primaryKey->value)->toBe('');
        expect($primaryKey->requiresValue())->toBeTrue();
        expect($primaryKey->isAutoIncrementing())->toBeFalse();
    });

    test('handles empty string value for Ulid type', function (): void {
        // Arrange
        $primaryKey = new PrimaryKeyValue(PrimaryKeyType::ULID, '');

        // Act & Assert
        expect($primaryKey->value)->toBe('');
        expect($primaryKey->requiresValue())->toBeTrue();
        expect($primaryKey->isAutoIncrementing())->toBeFalse();
    });

    test('readonly properties cannot be modified', function (): void {
        // Arrange
        $primaryKey = new PrimaryKeyValue(PrimaryKeyType::Id, null);

        // Act & Assert
        expect(fn (): PrimaryKeyType => $primaryKey->type = PrimaryKeyType::UUID)
            ->toThrow(Error::class);
    });
});
