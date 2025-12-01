<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\AuditDrivers\AuditDriverRegistry;
use Cline\Bearer\AuditDrivers\NullAuditDriver;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Exceptions\AuditDriverNotRegisteredException;
use Cline\Bearer\Exceptions\RevocationStrategyNotRegisteredException;
use Cline\Bearer\Exceptions\RotationStrategyNotRegisteredException;
use Cline\Bearer\RevocationStrategies\NoneStrategy;
use Cline\Bearer\RevocationStrategies\RevocationStrategyRegistry;
use Cline\Bearer\RotationStrategies\ImmediateInvalidationStrategy;
use Cline\Bearer\RotationStrategies\RotationStrategyRegistry;
use Illuminate\Support\Collection;

describe('RevocationStrategyRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers and retrieves a strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $strategy = new NoneStrategy();

            // Act
            $registry->register('none', $strategy);
            $retrieved = $registry->get('none');

            // Assert
            expect($retrieved)->toBe($strategy);
        });

        test('has() returns true for registered strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $registry->register('none', new NoneStrategy());

            // Act & Assert
            expect($registry->has('none'))->toBeTrue();
        });

        test('has() returns false for unregistered strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();

            // Act & Assert
            expect($registry->has('nonexistent'))->toBeFalse();
        });

        test('first registered strategy becomes default', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $strategy = new NoneStrategy();
            $registry->register('none', $strategy);

            // Act
            $default = $registry->default();

            // Assert
            expect($default)->toBe($strategy);
        });

        test('setDefault() changes the default strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $strategy1 = new NoneStrategy();
            $strategy2 = new class() implements RevocationStrategy
            {
                public function revoke(AccessToken $token): void {}

                public function getAffectedTokens(AccessToken $token): Collection
                {
                    return collect([$token]);
                }
            };
            $registry->register('none', $strategy1);
            $registry->register('custom', $strategy2);

            // Act
            $registry->setDefault('custom');

            // Assert
            expect($registry->default())->toBe($strategy2);
        });

        test('all() returns list of registered strategy names', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $registry->register('none', new NoneStrategy());
            $registry->register('custom', new class() implements RevocationStrategy
            {
                public function revoke(AccessToken $token): void {}

                public function getAffectedTokens(AccessToken $token): Collection
                {
                    return collect([$token]);
                }
            });

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toBe(['none', 'custom']);
        });
    });

    describe('Sad Path', function (): void {
        test('get() throws exception for unregistered strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();

            // Act & Assert
            expect(fn (): RevocationStrategy => $registry->get('nonexistent'))
                ->toThrow(RevocationStrategyNotRegisteredException::class);
        });

        test('default() throws exception when no strategies registered', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();

            // Act & Assert
            expect(fn (): RevocationStrategy => $registry->default())
                ->toThrow(RevocationStrategyNotRegisteredException::class);
        });

        test('setDefault() throws exception for unregistered strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();

            // Act & Assert
            expect(fn () => $registry->setDefault('nonexistent'))
                ->toThrow(RevocationStrategyNotRegisteredException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('re-registering same name overwrites previous strategy', function (): void {
            // Arrange
            $registry = new RevocationStrategyRegistry();
            $strategy1 = new NoneStrategy();
            $strategy2 = new class() implements RevocationStrategy
            {
                public function revoke(AccessToken $token): void {}

                public function getAffectedTokens(AccessToken $token): Collection
                {
                    return collect([$token]);
                }
            };

            // Act
            $registry->register('none', $strategy1);
            $registry->register('none', $strategy2);

            // Assert
            expect($registry->get('none'))->toBe($strategy2);
        });
    });
});

describe('RotationStrategyRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers and retrieves a strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $strategy = new ImmediateInvalidationStrategy();

            // Act
            $registry->register('immediate', $strategy);
            $retrieved = $registry->get('immediate');

            // Assert
            expect($retrieved)->toBe($strategy);
        });

        test('has() returns true for registered strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $registry->register('immediate', new ImmediateInvalidationStrategy());

            // Act & Assert
            expect($registry->has('immediate'))->toBeTrue();
        });

        test('has() returns false for unregistered strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();

            // Act & Assert
            expect($registry->has('nonexistent'))->toBeFalse();
        });

        test('first registered strategy becomes default', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $strategy = new ImmediateInvalidationStrategy();
            $registry->register('immediate', $strategy);

            // Act
            $default = $registry->default();

            // Assert
            expect($default)->toBe($strategy);
        });

        test('setDefault() changes the default strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $strategy1 = new ImmediateInvalidationStrategy();
            $strategy2 = new class() implements RotationStrategy
            {
                public function rotate(AccessToken $oldToken, AccessToken $newToken): void {}

                public function isOldTokenValid(AccessToken $oldToken): bool
                {
                    return true;
                }

                public function gracePeriodMinutes(): ?int
                {
                    return null;
                }
            };
            $registry->register('immediate', $strategy1);
            $registry->register('custom', $strategy2);

            // Act
            $registry->setDefault('custom');

            // Assert
            expect($registry->default())->toBe($strategy2);
        });

        test('all() returns list of registered strategy names', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $registry->register('immediate', new ImmediateInvalidationStrategy());
            $registry->register('custom', new class() implements RotationStrategy
            {
                public function rotate(AccessToken $oldToken, AccessToken $newToken): void {}

                public function isOldTokenValid(AccessToken $oldToken): bool
                {
                    return true;
                }

                public function gracePeriodMinutes(): ?int
                {
                    return null;
                }
            });

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toBe(['immediate', 'custom']);
        });
    });

    describe('Sad Path', function (): void {
        test('get() throws exception for unregistered strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();

            // Act & Assert
            expect(fn (): RotationStrategy => $registry->get('nonexistent'))
                ->toThrow(RotationStrategyNotRegisteredException::class);
        });

        test('default() throws exception when no strategies registered', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();

            // Act & Assert
            expect(fn (): RotationStrategy => $registry->default())
                ->toThrow(RotationStrategyNotRegisteredException::class);
        });

        test('setDefault() throws exception for unregistered strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();

            // Act & Assert
            expect(fn () => $registry->setDefault('nonexistent'))
                ->toThrow(RotationStrategyNotRegisteredException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('re-registering same name overwrites previous strategy', function (): void {
            // Arrange
            $registry = new RotationStrategyRegistry();
            $strategy1 = new ImmediateInvalidationStrategy();
            $strategy2 = new class() implements RotationStrategy
            {
                public function rotate(AccessToken $oldToken, AccessToken $newToken): void {}

                public function isOldTokenValid(AccessToken $oldToken): bool
                {
                    return true;
                }

                public function gracePeriodMinutes(): ?int
                {
                    return null;
                }
            };

            // Act
            $registry->register('immediate', $strategy1);
            $registry->register('immediate', $strategy2);

            // Assert
            expect($registry->get('immediate'))->toBe($strategy2);
        });
    });
});

describe('AuditDriverRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers and retrieves a driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $driver = new NullAuditDriver();

            // Act
            $registry->register('null', $driver);
            $retrieved = $registry->get('null');

            // Assert
            expect($retrieved)->toBe($driver);
        });

        test('has() returns true for registered driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $registry->register('null', new NullAuditDriver());

            // Act & Assert
            expect($registry->has('null'))->toBeTrue();
        });

        test('has() returns false for unregistered driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();

            // Act & Assert
            expect($registry->has('nonexistent'))->toBeFalse();
        });

        test('first registered driver becomes default', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $driver = new NullAuditDriver();
            $registry->register('null', $driver);

            // Act
            $default = $registry->default();

            // Assert
            expect($default)->toBe($driver);
        });

        test('setDefault() changes the default driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $driver1 = new NullAuditDriver();
            $driver2 = new class() implements AuditDriver
            {
                public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void {}

                public function getLogsForToken(AccessToken $token): Collection
                {
                    return collect();
                }
            };
            $registry->register('null', $driver1);
            $registry->register('custom', $driver2);

            // Act
            $registry->setDefault('custom');

            // Assert
            expect($registry->default())->toBe($driver2);
        });

        test('all() returns list of registered driver names', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $registry->register('null', new NullAuditDriver());
            $registry->register('custom', new class() implements AuditDriver
            {
                public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void {}

                public function getLogsForToken(AccessToken $token): Collection
                {
                    return collect();
                }
            });

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toBe(['null', 'custom']);
        });
    });

    describe('Sad Path', function (): void {
        test('get() throws exception for unregistered driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();

            // Act & Assert
            expect(fn (): AuditDriver => $registry->get('nonexistent'))
                ->toThrow(AuditDriverNotRegisteredException::class);
        });

        test('default() throws exception when no drivers registered', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();

            // Act & Assert
            expect(fn (): AuditDriver => $registry->default())
                ->toThrow(AuditDriverNotRegisteredException::class);
        });

        test('setDefault() throws exception for unregistered driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();

            // Act & Assert
            expect(fn () => $registry->setDefault('nonexistent'))
                ->toThrow(AuditDriverNotRegisteredException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('re-registering same name overwrites previous driver', function (): void {
            // Arrange
            $registry = new AuditDriverRegistry();
            $driver1 = new NullAuditDriver();
            $driver2 = new class() implements AuditDriver
            {
                public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void {}

                public function getLogsForToken(AccessToken $token): Collection
                {
                    return collect();
                }
            };

            // Act
            $registry->register('null', $driver1);
            $registry->register('null', $driver2);

            // Assert
            expect($registry->get('null'))->toBe($driver2);
        });
    });
});
