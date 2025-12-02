<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Exceptions\TokenGeneratorNotRegisteredException;
use Cline\Bearer\TokenGenerators\RandomTokenGenerator;
use Cline\Bearer\TokenGenerators\SeamTokenGenerator;
use Cline\Bearer\TokenGenerators\TokenGeneratorRegistry;
use Cline\Bearer\TokenGenerators\UuidTokenGenerator;

describe('TokenGeneratorRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers and retrieves token generators', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $retrieved = $registry->get('seam');

            // Assert
            expect($retrieved)->toBe($seamGenerator);
        });

        test('checks if token generator exists', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $registry->register('seam', new SeamTokenGenerator());

            // Act & Assert
            expect($registry->has('seam'))->toBeTrue();
            expect($registry->has('nonexistent'))->toBeFalse();
        });

        test('sets first registered generator as default', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $defaultGenerator = $registry->default();

            // Assert
            expect($defaultGenerator)->toBe($seamGenerator);
        });

        test('retrieves default generator', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();
            $uuidGenerator = new UuidTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $registry->register('uuid', $uuidGenerator);

            $defaultGenerator = $registry->default();

            // Assert
            expect($defaultGenerator)->toBe($seamGenerator);
        });

        test('changes default generator', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();
            $uuidGenerator = new UuidTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $registry->register('uuid', $uuidGenerator);
            $registry->setDefault('uuid');

            $defaultGenerator = $registry->default();

            // Assert
            expect($defaultGenerator)->toBe($uuidGenerator);
        });

        test('lists all registered generator names', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();

            // Act
            $registry->register('seam', new SeamTokenGenerator());
            $registry->register('uuid', new UuidTokenGenerator());
            $registry->register('random', new RandomTokenGenerator());

            $names = $registry->all();

            // Assert
            expect($names)->toBe(['seam', 'uuid', 'random']);
        });

        test('returns empty array when no generators registered', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();

            // Act
            $names = $registry->all();

            // Assert
            expect($names)->toBe([]);
        });
    });

    describe('Sad Path', function (): void {
        test('throws exception when getting unregistered generator', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();

            // Act & Assert
            expect(fn (): TokenGenerator => $registry->get('nonexistent'))
                ->toThrow(
                    TokenGeneratorNotRegisteredException::class,
                    'Token generator "nonexistent" is not registered.',
                );
        });

        test('throws exception when getting default with no generators registered', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();

            // Act & Assert
            expect(fn (): TokenGenerator => $registry->default())
                ->toThrow(
                    TokenGeneratorNotRegisteredException::class,
                    'No default token generator is registered.',
                );
        });

        test('throws exception when setting unregistered generator as default', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $registry->register('seam', new SeamTokenGenerator());

            // Act & Assert
            expect(fn () => $registry->setDefault('nonexistent'))
                ->toThrow(
                    TokenGeneratorNotRegisteredException::class,
                    'Cannot set unregistered generator "nonexistent" as default.',
                );
        });
    });

    describe('Edge Cases', function (): void {
        test('overwrites generator when registering with same name', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $firstGenerator = new SeamTokenGenerator();
            $secondGenerator = new UuidTokenGenerator();

            // Act
            $registry->register('generator', $firstGenerator);
            $registry->register('generator', $secondGenerator);

            $retrieved = $registry->get('generator');

            // Assert
            expect($retrieved)->toBe($secondGenerator);
            expect($retrieved)->not->toBe($firstGenerator);
        });

        test('maintains default when overwriting non-default generator', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();
            $uuidGenerator = new UuidTokenGenerator();
            $randomGenerator = new RandomTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $registry->register('uuid', $uuidGenerator);
            $registry->register('uuid', $randomGenerator);
            // Overwrite uuid
            $defaultGenerator = $registry->default();

            // Assert
            expect($defaultGenerator)->toBe($seamGenerator); // Default is still seam
        });

        test('allows setting same generator as default multiple times', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $seamGenerator = new SeamTokenGenerator();

            // Act
            $registry->register('seam', $seamGenerator);
            $registry->setDefault('seam');
            $registry->setDefault('seam');

            $defaultGenerator = $registry->default();

            // Assert
            expect($defaultGenerator)->toBe($seamGenerator);
        });

        test('handles generator name with special characters', function (): void {
            // Arrange
            $registry = new TokenGeneratorRegistry();
            $generator = new SeamTokenGenerator();

            // Act
            $registry->register('my-special_generator.v1', $generator);

            // Assert
            expect($registry->has('my-special_generator.v1'))->toBeTrue();
            expect($registry->get('my-special_generator.v1'))->toBe($generator);
        });
    });
});
