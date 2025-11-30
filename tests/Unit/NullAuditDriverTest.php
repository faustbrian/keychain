<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\AuditDrivers\NullAuditDriver;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Support\Collection;

describe('NullAuditDriver', function (): void {
    beforeEach(function (): void {
        $this->driver = new NullAuditDriver();
        $this->user = createUser();
        $this->token = createToken($this->user);
    });

    it('implements AuditDriver contract', function (): void {
        expect($this->driver)->toBeInstanceOf(AuditDriver::class);
    });

    it('can be instantiated without dependencies', function (): void {
        $driver = new NullAuditDriver();

        expect($driver)->toBeInstanceOf(NullAuditDriver::class);
        expect($driver)->toBeInstanceOf(AuditDriver::class);
    });

    describe('log()', function (): void {
        it('does nothing when logging events', function (): void {
            // Arrange
            $event = AuditEvent::Created;
            $context = ['ip_address' => '192.168.1.1', 'user_agent' => 'TestAgent/1.0'];

            // Act
            $this->driver->log($this->token, $event, $context);

            // Assert - no exception thrown, operation completes silently
            expect(true)->toBeTrue();
        });

        it('accepts all audit event types without side effects', function (): void {
            // Arrange
            $events = [
                AuditEvent::Created,
                AuditEvent::Authenticated,
                AuditEvent::Revoked,
                AuditEvent::Rotated,
                AuditEvent::Failed,
                AuditEvent::RateLimited,
                AuditEvent::IpBlocked,
                AuditEvent::DomainBlocked,
                AuditEvent::Expired,
            ];

            // Act & Assert
            foreach ($events as $event) {
                $this->driver->log($this->token, $event);
                expect(true)->toBeTrue(); // No exception thrown
            }
        });

        it('accepts empty context array', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;

            // Act
            $this->driver->log($this->token, $event, []);

            // Assert
            expect(true)->toBeTrue();
        });

        it('accepts context with various data types', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;
            $context = [
                'ip_address' => '127.0.0.1',
                'user_agent' => 'Mozilla/5.0',
                'response_time' => 145,
                'success' => true,
                'metadata' => ['key' => 'value'],
            ];

            // Act
            $this->driver->log($this->token, $event, $context);

            // Assert
            expect(true)->toBeTrue();
        });

        it('handles multiple consecutive log calls', function (): void {
            // Arrange
            $events = [
                AuditEvent::Created,
                AuditEvent::Authenticated,
                AuditEvent::Failed,
            ];

            // Act
            foreach ($events as $event) {
                $this->driver->log($this->token, $event);
            }

            // Assert - verify no accumulation by checking logs are empty
            $logs = $this->driver->getLogsForToken($this->token);
            expect($logs)->toBeEmpty();
        });

        it('works with different token instances', function (): void {
            // Arrange
            $token1 = createToken($this->user, 'sk', ['name' => 'Token 1']);
            $token2 = createToken($this->user, 'sk', ['name' => 'Token 2']);

            // Act
            $this->driver->log($token1, AuditEvent::Created);
            $this->driver->log($token2, AuditEvent::Authenticated);

            // Assert
            expect($this->driver->getLogsForToken($token1))->toBeEmpty();
            expect($this->driver->getLogsForToken($token2))->toBeEmpty();
        });
    });

    describe('getLogsForToken()', function (): void {
        it('returns empty collection', function (): void {
            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs)->toBeInstanceOf(Collection::class);
            expect($logs)->toBeEmpty();
            expect($logs->count())->toBe(0);
        });

        it('always returns empty collection regardless of prior log calls', function (): void {
            // Arrange
            $this->driver->log($this->token, AuditEvent::Created);
            $this->driver->log($this->token, AuditEvent::Authenticated);
            $this->driver->log($this->token, AuditEvent::Revoked);

            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs)->toBeEmpty();
        });

        it('returns empty collection for different tokens', function (): void {
            // Arrange
            $token1 = createToken($this->user, 'sk', ['name' => 'Token 1']);
            $token2 = createToken($this->user, 'sk', ['name' => 'Token 2']);

            $this->driver->log($token1, AuditEvent::Created);
            $this->driver->log($token2, AuditEvent::Created);

            // Act & Assert
            expect($this->driver->getLogsForToken($token1))->toBeEmpty();
            expect($this->driver->getLogsForToken($token2))->toBeEmpty();
        });

        it('returns independent collection instances', function (): void {
            // Act
            $logs1 = $this->driver->getLogsForToken($this->token);
            $logs2 = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs1)->not->toBe($logs2); // Different instances
            expect($logs1)->toBeEmpty();
            expect($logs2)->toBeEmpty();
        });
    });

    describe('no-op behavior verification', function (): void {
        it('does not create database records', function (): void {
            // Arrange
            $initialCount = AccessTokenAuditLog::query()->count();

            // Act
            $this->driver->log($this->token, AuditEvent::Created);
            $this->driver->log($this->token, AuditEvent::Authenticated);
            $this->driver->log($this->token, AuditEvent::Revoked);

            // Assert
            $finalCount = AccessTokenAuditLog::query()->count();
            expect($finalCount)->toBe($initialCount);
        });

        it('has zero performance overhead', function (): void {
            // Arrange
            $startTime = microtime(true);

            // Act - perform many operations
            for ($i = 0; $i < 1_000; ++$i) {
                $this->driver->log($this->token, AuditEvent::Authenticated);
            }

            $endTime = microtime(true);
            $duration = $endTime - $startTime;

            // Assert - should complete nearly instantaneously (less than 50ms for 1000 calls)
            expect($duration)->toBeLessThan(0.05);
        });

        it('does not maintain internal state', function (): void {
            // Arrange & Act
            $this->driver->log($this->token, AuditEvent::Created);
            $this->driver->log($this->token, AuditEvent::Authenticated);

            // Assert - verify no state by getting empty logs
            $logs = $this->driver->getLogsForToken($this->token);
            expect($logs)->toBeEmpty();

            // Act - log more events
            $this->driver->log($this->token, AuditEvent::Revoked);

            // Assert - still no state
            $logs = $this->driver->getLogsForToken($this->token);
            expect($logs)->toBeEmpty();
        });

        it('can handle rapid successive calls', function (): void {
            // Act
            for ($i = 0; $i < 100; ++$i) {
                $this->driver->log($this->token, AuditEvent::Authenticated);
                $logs = $this->driver->getLogsForToken($this->token);
                expect($logs)->toBeEmpty();
            }

            // Assert
            expect(true)->toBeTrue(); // No errors occurred
        });
    });

    describe('use case scenarios', function (): void {
        it('works for testing environments without audit overhead', function (): void {
            // Arrange - simulate test scenario
            $testToken = createToken($this->user, 'sk', ['name' => 'Test Token']);

            // Act - perform various operations that would normally create logs
            $this->driver->log($testToken, AuditEvent::Created, ['environment' => 'test']);
            $this->driver->log($testToken, AuditEvent::Authenticated, ['test_mode' => true]);

            // Assert - no logs created
            expect($this->driver->getLogsForToken($testToken))->toBeEmpty();
        });

        it('works for development environments to reduce database writes', function (): void {
            // Arrange - simulate high-frequency operations
            $devToken = createToken($this->user, 'sk', ['name' => 'Dev Token']);

            // Act - simulate many authentication attempts
            for ($i = 0; $i < 50; ++$i) {
                $this->driver->log($devToken, AuditEvent::Authenticated);
            }

            // Assert - no database overhead
            expect($this->driver->getLogsForToken($devToken))->toBeEmpty();
        });

        it('works for performance-critical applications', function (): void {
            // Arrange
            $perfToken = createToken($this->user, 'sk', ['name' => 'Perf Token']);

            // Act - measure time for many operations
            $startTime = microtime(true);

            for ($i = 0; $i < 500; ++$i) {
                $this->driver->log($perfToken, AuditEvent::Authenticated, [
                    'request_id' => 'req_'.$i,
                    'endpoint' => '/api/users',
                ]);
            }

            $duration = microtime(true) - $startTime;

            // Assert - extremely fast execution
            expect($duration)->toBeLessThan(0.1); // Less than 100ms for 500 operations
        });

        it('supports temporary disabling of audit logging', function (): void {
            // Arrange - simulate switching from database driver to null driver
            $token = createToken($this->user, 'sk', ['name' => 'Switchable Token']);

            // Act - use null driver (would normally use database driver)
            $this->driver->log($token, AuditEvent::Created);
            $this->driver->log($token, AuditEvent::Authenticated);

            // Assert - no logs accumulated
            $logs = $this->driver->getLogsForToken($token);
            expect($logs)->toBeEmpty();
        });

        it('works as mock implementation in unit tests', function (): void {
            // Arrange - simulate testing code that depends on AuditDriver
            $mockDriver = new NullAuditDriver();
            $testToken = createToken($this->user, 'sk', ['name' => 'Mock Token']);

            // Act - code under test calls driver methods
            $mockDriver->log($testToken, AuditEvent::Authenticated);
            $result = $mockDriver->getLogsForToken($testToken);

            // Assert - predictable no-op behavior
            expect($result)->toBeEmpty();
            expect($mockDriver)->toBeInstanceOf(AuditDriver::class);
        });
    });
});
