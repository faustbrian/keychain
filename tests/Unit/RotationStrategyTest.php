<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\RotationStrategies\DualValidStrategy;
use Cline\Bearer\RotationStrategies\GracePeriodStrategy;
use Cline\Bearer\RotationStrategies\ImmediateInvalidationStrategy;
use Illuminate\Support\Facades\Date;
use Tests\Fixtures\User;

function createTestToken(User $user, array $attributes = []): AccessToken
{
    static $counter = 0;
    ++$counter;

    return AccessToken::query()->forceCreate(array_merge([
        'owner_type' => User::class,
        'owner_id' => $user->id,
        'type' => 'secret_key',
        'environment' => 'test',
        'name' => 'Test Token '.$counter,
        'prefix' => 'sk_test',
        'token' => 'test-token-hash-'.uniqid(),
        'abilities' => ['*'],
    ], $attributes));
}

describe('DualValidStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('rotate() does nothing and both tokens remain valid', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at)->toBeNull();
            expect($newToken->revoked_at)->toBeNull();
        });

        test('isOldTokenValid() returns true when token is not revoked', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeTrue();
        });

        test('isOldTokenValid() returns false when token is revoked', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::parse('2024-01-15 10:00:00')]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('gracePeriodMinutes() returns null', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();

            // Act
            $result = $strategy->gracePeriodMinutes();

            // Assert
            expect($result)->toBeNull();
        });

        test('both tokens remain valid after rotation', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            expect($strategy->isOldTokenValid($oldToken))->toBeTrue();
            expect($newToken->isValid())->toBeTrue();
        });
    });

    describe('Sad Path', function (): void {
        test('isOldTokenValid() returns false for already revoked token', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->subHours(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('isOldTokenValid() returns false when manually revoked after rotation', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);
            $oldToken->update(['revoked_at' => Date::now()]);

            // Assert
            expect($strategy->isOldTokenValid($oldToken))->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('handles token with future revocation date', function (): void {
            // Arrange
            $strategy = new DualValidStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->addHours(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });
    });
});

describe('GracePeriodStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('uses default 60 minute grace period', function (): void {
            // Arrange
            $strategy = new GracePeriodStrategy(60);

            // Act
            $result = $strategy->gracePeriodMinutes();

            // Assert
            expect($result)->toBe(60);
        });

        test('uses custom grace period', function (): void {
            // Arrange
            $customPeriod = 120;
            $strategy = new GracePeriodStrategy($customPeriod);

            // Act
            $result = $strategy->gracePeriodMinutes();

            // Assert
            expect($result)->toBe(120);
        });

        test('rotate() sets revoked_at to future time based on grace period', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at)->not->toBeNull();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 11:00:00');
        });

        test('isOldTokenValid() returns true when revoked_at is in future', function (): void {
            // Arrange
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->addMinutes(30)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeTrue();
        });

        test('isOldTokenValid() returns false when revoked_at is in past', function (): void {
            // Arrange
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->subMinutes(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('isOldTokenValid() returns true when revoked_at is null', function (): void {
            // Arrange
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeTrue();
        });

        test('rotate() with custom grace period sets correct future time', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new GracePeriodStrategy(30);
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 10:30:00');
        });
    });

    describe('Sad Path', function (): void {
        test('isOldTokenValid() returns false when grace period has expired', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 12:00:00');
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::parse('2024-01-15 11:00:00')]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('token becomes invalid after grace period expires', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);
            $oldToken->refresh();
            expect($strategy->isOldTokenValid($oldToken))->toBeTrue();

            Date::setTestNow('2024-01-15 11:01:00');

            // Assert
            expect($strategy->isOldTokenValid($oldToken))->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('handles zero minute grace period', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new GracePeriodStrategy(0);
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 10:00:00');
            expect($strategy->gracePeriodMinutes())->toBe(0);
        });

        test('handles very long grace period', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new GracePeriodStrategy(10_080); // 7 days in minutes
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-22 10:00:00');
            expect($strategy->gracePeriodMinutes())->toBe(10_080);
        });

        test('isOldTokenValid() handles exact moment when grace period expires', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 11:00:00');
            $strategy = new GracePeriodStrategy(60);
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::parse('2024-01-15 11:00:00')]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });
    });
});

describe('ImmediateInvalidationStrategy', function (): void {
    describe('Happy Path', function (): void {
        test('rotate() sets revoked_at to current time', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at)->not->toBeNull();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 10:00:00');
        });

        test('isOldTokenValid() always returns false', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('isOldTokenValid() returns false even when token not revoked', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('isOldTokenValid() returns false when token is revoked', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('gracePeriodMinutes() returns null', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();

            // Act
            $result = $strategy->gracePeriodMinutes();

            // Assert
            expect($result)->toBeNull();
        });

        test('old token is immediately invalid after rotation', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->isRevoked())->toBeTrue();
            expect($strategy->isOldTokenValid($oldToken))->toBeFalse();
        });
    });

    describe('Sad Path', function (): void {
        test('isOldTokenValid() returns false for already revoked token', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->subHours(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('rotate() overwrites existing revoked_at timestamp', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::parse('2024-01-10 10:00:00')]);

            $newToken = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 10:00:00');
        });
    });

    describe('Edge Cases', function (): void {
        test('isOldTokenValid() returns false with future revoked_at', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->addHours(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('isOldTokenValid() returns false with past revoked_at', function (): void {
            // Arrange
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $oldToken->update(['revoked_at' => Date::now()->subHours(1)]);

            // Act
            $result = $strategy->isOldTokenValid($oldToken);

            // Assert
            expect($result)->toBeFalse();
        });

        test('multiple rotations update revoked_at each time', function (): void {
            // Arrange
            Date::setTestNow('2024-01-15 10:00:00');
            $strategy = new ImmediateInvalidationStrategy();
            $user = createUser();
            $oldToken = createTestToken($user);
            $newToken1 = createTestToken($user);

            // Act
            $strategy->rotate($oldToken, $newToken1);
            $oldToken->refresh();
            $firstRevocation = $oldToken->revoked_at;

            Date::setTestNow('2024-01-15 11:00:00');
            $newToken2 = createTestToken($user);
            $strategy->rotate($oldToken, $newToken2);

            // Assert
            $oldToken->refresh();
            expect($oldToken->revoked_at->format('Y-m-d H:i:s'))->toBe('2024-01-15 11:00:00');
            expect($oldToken->revoked_at)->not->toEqual($firstRevocation);
        });
    });
});
