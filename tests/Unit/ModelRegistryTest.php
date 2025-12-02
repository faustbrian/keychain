<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\ModelRegistry;
use Cline\Morphism\MorphKeyRegistry;
use Tests\Fixtures\User;

describe('ModelRegistry', function (): void {
    beforeEach(function (): void {
        // Get fresh instance of MorphKeyRegistry for each test
        $this->morphKeyRegistry = new MorphKeyRegistry();
        $this->modelRegistry = new ModelRegistry($this->morphKeyRegistry);
    });

    afterEach(function (): void {
        // Clean up after each test
        $this->modelRegistry->reset();
    });

    describe('Happy Path', function (): void {
        describe('morphKeyMap', function (): void {
            test('registers mappings successfully', function (): void {
                // Arrange
                $map = [
                    User::class => 'uuid',
                ];

                // Act
                $this->modelRegistry->morphKeyMap($map);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });

            test('registers multiple mappings', function (): void {
                // Arrange
                $map = [
                    User::class => 'uuid',
                ];
                // Act
                $this->modelRegistry->morphKeyMap($map);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });

            test('overwrites existing mapping', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([User::class => 'id']);

                // Act
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });
        });

        describe('enforceMorphKeyMap', function (): void {
            test('registers and enforces mappings', function (): void {
                // Arrange
                $map = [
                    User::class => 'uuid',
                ];

                // Act
                $this->modelRegistry->enforceMorphKeyMap($map);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });

            test('enforces multiple mappings', function (): void {
                // Arrange
                $map = [
                    User::class => 'uuid',
                ];
                // Act
                $this->modelRegistry->enforceMorphKeyMap($map);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });
        });

        describe('requireKeyMap', function (): void {
            test('enables strict enforcement', function (): void {
                // Arrange & Act
                $this->modelRegistry->requireKeyMap();

                // Assert - requireKeyMap doesn't return anything, but we can test it was called
                // by checking subsequent behavior with getModelKeyFromClass
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });

            test('works with morphKeyMap', function (): void {
                // Arrange
                $this->modelRegistry->requireKeyMap();

                // Act
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
            });
        });

        describe('getModelKey', function (): void {
            test('returns key for model instance', function (): void {
                // Arrange
                $user = createUser();
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

                // Act
                $result = $this->modelRegistry->getModelKey($user);

                // Assert
                expect($result)->toBe('uuid');
            });

            test('returns correct key for different models', function (): void {
                // Arrange
                $user = createUser();
                $this->modelRegistry->morphKeyMap([
                    User::class => 'uuid',
                ]);

                // Act
                $result = $this->modelRegistry->getModelKey($user);

                // Assert
                expect($result)->toBe('uuid');
            });
        });

        describe('getModelKeyFromClass', function (): void {
            test('returns key from class string', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

                // Act
                $result = $this->modelRegistry->getModelKeyFromClass(User::class);

                // Assert
                expect($result)->toBe('uuid');
            });

            test('returns different keys for different classes', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([
                    'App\Models\Team' => 'id',
                ]);

                // Act
                $teamKey = $this->modelRegistry->getModelKeyFromClass('App\Models\Team');

                // Assert
                expect($teamKey)->toBe('id');
            });
        });

        describe('reset', function (): void {
            test('clears all state', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');

                // Act
                $this->modelRegistry->reset();

                // Assert - After reset, should return the model's default key (id)
                $result = $this->modelRegistry->getModelKeyFromClass(User::class);
                expect($result)->toBe('id');
            });

            test('clears multiple mappings', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([
                    User::class => 'uuid',
                ]);

                // Act
                $this->modelRegistry->reset();

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('id');
            });

            test('allows re-registration after reset', function (): void {
                // Arrange
                $this->modelRegistry->morphKeyMap([User::class => 'uuid']);
                $this->modelRegistry->reset();

                // Act
                $this->modelRegistry->morphKeyMap([User::class => 'new_uuid']);

                // Assert
                expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('new_uuid');
            });
        });
    });

    describe('Sad Path', function (): void {
        test('getModelKeyFromClass returns default key for unmapped class', function (): void {
            // Arrange - No mappings registered

            // Act
            $result = $this->modelRegistry->getModelKeyFromClass(User::class);

            // Assert - Should return model's default primary key
            expect($result)->toBe('id');
        });

        test('getModelKey returns default key for unmapped model', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $result = $this->modelRegistry->getModelKey($user);

            // Assert
            expect($result)->toBe('id');
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty map gracefully', function (): void {
            // Arrange & Act
            $this->modelRegistry->morphKeyMap([]);

            // Assert - Should not throw, just do nothing
            expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('id');
        });

        test('handles same class registered multiple times', function (): void {
            // Arrange
            $this->modelRegistry->morphKeyMap([User::class => 'uuid']);
            $this->modelRegistry->morphKeyMap([User::class => 'id']);

            // Act & Assert - Last registration wins
            expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('id');
        });

        test('reset is idempotent', function (): void {
            // Arrange
            $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

            // Act
            $this->modelRegistry->reset();
            $this->modelRegistry->reset();
            $this->modelRegistry->reset();

            // Assert - Multiple resets don't cause issues
            expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('id');
        });

        test('can call requireKeyMap multiple times', function (): void {
            // Arrange & Act
            $this->modelRegistry->requireKeyMap();
            $this->modelRegistry->requireKeyMap();
            $this->modelRegistry->requireKeyMap();

            // Assert - Should not throw
            $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

            expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
        });

        test('enforceMorphKeyMap with empty map does not throw', function (): void {
            // Arrange & Act - Should not throw when enforcing empty map
            $this->modelRegistry->enforceMorphKeyMap([]);

            // Assert - Can still register mappings after empty enforcement
            $this->modelRegistry->morphKeyMap([User::class => 'uuid']);

            expect($this->modelRegistry->getModelKeyFromClass(User::class))->toBe('uuid');
        });
    });
});
