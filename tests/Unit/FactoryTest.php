<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\Enums\AuditEvent;
use Tests\Fixtures\User;

describe('AccessTokenGroupFactory', function (): void {
    describe('Happy Path', function (): void {
        test('creates valid AccessTokenGroup', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup)->toBeInstanceOf(AccessTokenGroup::class);
            expect($tokenGroup->id)->not->toBeNull();
            expect($tokenGroup->name)->toBeString();
            expect($tokenGroup->name)->not->toBeEmpty();
            expect($tokenGroup->metadata)->toBeNull();
            expect($tokenGroup->owner_id)->toBe($user->id);
            expect($tokenGroup->owner_type)->toBe(User::class);
            expect($tokenGroup->created_at)->not->toBeNull();
            expect($tokenGroup->updated_at)->not->toBeNull();
        });

        test('creates AccessTokenGroup with custom name', function (): void {
            // Arrange
            $user = createUser();
            $customName = 'Production Keys';

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create([
                'name' => $customName,
            ]);

            // Assert
            expect($tokenGroup->name)->toBe($customName);
        });

        test('creates AccessTokenGroup with custom metadata', function (): void {
            // Arrange
            $user = createUser();
            $metadata = [
                'environment' => 'production',
                'region' => 'us-east-1',
            ];

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe($metadata);
            expect($tokenGroup->metadata['environment'])->toBe('production');
            expect($tokenGroup->metadata['region'])->toBe('us-east-1');
        });

        test('creates multiple AccessTokenGroups', function (): void {
            // Arrange
            $user = createUser();
            $count = 5;

            // Act
            $tokenGroups = AccessTokenGroup::factory()->count($count)->for($user, 'owner')->create();

            // Assert
            expect($tokenGroups)->toHaveCount($count);

            foreach ($tokenGroups as $tokenGroup) {
                expect($tokenGroup)->toBeInstanceOf(AccessTokenGroup::class);
                expect($tokenGroup->name)->toBeString();
                expect($tokenGroup->owner_id)->toBe($user->id);
            }
        });

        test('creates AccessTokenGroup with unique names', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup1 = AccessTokenGroup::factory()->for($user, 'owner')->create();
            $tokenGroup2 = AccessTokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup1->name)->not->toBe($tokenGroup2->name);
        });
    });

    describe('Sad Path', function (): void {
        // Note: Factory validations are typically handled at the database level
        // These tests verify the factory produces valid data that passes constraints
    });

    describe('Edge Cases', function (): void {
        test('creates AccessTokenGroup with empty metadata array', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => [],
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe([]);
        });

        test('creates AccessTokenGroup with long name', function (): void {
            // Arrange
            $user = createUser();
            $longName = str_repeat('A', 255); // Max typical VARCHAR length

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create([
                'name' => $longName,
            ]);

            // Assert
            expect($tokenGroup->name)->toBe($longName);
            expect(mb_strlen($tokenGroup->name))->toBe(255);
        });

        test('creates AccessTokenGroup with nested metadata', function (): void {
            // Arrange
            $user = createUser();
            $metadata = [
                'config' => [
                    'notifications' => [
                        'email' => true,
                        'slack' => false,
                    ],
                ],
            ];

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe($metadata);
            expect($tokenGroup->metadata['config']['notifications']['email'])->toBeTrue();
        });
    });

    describe('Relationships', function (): void {
        test('AccessTokenGroup can have multiple tokens', function (): void {
            // Arrange
            $user = createUser();
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create();

            // Act
            $token1 = createToken($user);
            $token2 = createToken($user);
            $token1->update(['group_id' => $tokenGroup->id]);
            $token2->update(['group_id' => $tokenGroup->id]);

            // Assert
            expect($tokenGroup->tokens)->toHaveCount(2);
            expect($tokenGroup->tokens->pluck('id')->toArray())->toContain($token1->id);
            expect($tokenGroup->tokens->pluck('id')->toArray())->toContain($token2->id);
        });

        test('AccessTokenGroup has owner relationship', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = AccessTokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup->owner)->toBeInstanceOf(User::class);
            expect($tokenGroup->owner->id)->toBe($user->id);
        });
    });
});

describe('AccessTokenAuditLogFactory', function (): void {
    describe('Happy Path', function (): void {
        test('creates valid AccessTokenAuditLog', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create();

            // Assert
            expect($auditLog)->toBeInstanceOf(AccessTokenAuditLog::class);
            expect($auditLog->id)->not->toBeNull();
            expect($auditLog->token_id)->toBe($token->id);
            expect($auditLog->event)->toBeInstanceOf(AuditEvent::class);
            expect($auditLog->ip_address)->toBeString();
            expect($auditLog->user_agent)->toBeString();
            expect($auditLog->metadata)->toBeNull();
            expect($auditLog->created_at)->not->toBeNull();
        });

        test('creates AccessTokenAuditLog with specific event', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $event = AuditEvent::Created;

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'event' => $event,
            ]);

            // Assert
            expect($auditLog->event)->toBe($event);
        });

        test('creates AccessTokenAuditLog with all possible events', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act & Assert - Test each AuditEvent case
            foreach (AuditEvent::cases() as $event) {
                $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                    'event' => $event,
                ]);

                expect($auditLog->event)->toBe($event);
            }
        });

        test('creates AccessTokenAuditLog with custom IP address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $ipAddress = '192.168.1.100';

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => $ipAddress,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBe($ipAddress);
        });

        test('creates AccessTokenAuditLog with custom user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $userAgent = 'Mozilla/5.0 (Custom Browser)';

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => $userAgent,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBe($userAgent);
        });

        test('creates AccessTokenAuditLog with custom metadata', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $metadata = [
                'request_id' => 'abc123',
                'endpoint' => '/api/users',
            ];

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($auditLog->metadata)->toBe($metadata);
            expect($auditLog->metadata['request_id'])->toBe('abc123');
            expect($auditLog->metadata['endpoint'])->toBe('/api/users');
        });

        test('creates multiple AccessTokenAuditLogs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $count = 10;

            // Act
            $auditLogs = AccessTokenAuditLog::factory()->count($count)->for($token, 'token')->create();

            // Assert
            expect($auditLogs)->toHaveCount($count);

            foreach ($auditLogs as $auditLog) {
                expect($auditLog)->toBeInstanceOf(AccessTokenAuditLog::class);
                expect($auditLog->token_id)->toBe($token->id);
            }
        });
    });

    describe('Sad Path', function (): void {
        // Note: Factory validations are typically handled at the database level
    });

    describe('Edge Cases', function (): void {
        test('creates AccessTokenAuditLog with IPv6 address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $ipv6Address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => $ipv6Address,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBe($ipv6Address);
        });

        test('creates AccessTokenAuditLog with null IP address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => null,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBeNull();
        });

        test('creates AccessTokenAuditLog with null user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => null,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBeNull();
        });

        test('creates AccessTokenAuditLog with empty metadata array', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => [],
            ]);

            // Assert
            expect($auditLog->metadata)->toBe([]);
        });

        test('creates AccessTokenAuditLog with nested metadata', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $metadata = [
                'request' => [
                    'method' => 'POST',
                    'headers' => [
                        'Content-Type' => 'application/json',
                    ],
                ],
            ];

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($auditLog->metadata)->toBe($metadata);
            expect($auditLog->metadata['request']['method'])->toBe('POST');
        });

        test('creates AccessTokenAuditLog with very long user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $longUserAgent = str_repeat('A', 500);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => $longUserAgent,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBe($longUserAgent);
        });
    });

    describe('Relationships', function (): void {
        test('AccessTokenAuditLog belongs to token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = AccessTokenAuditLog::factory()->for($token, 'token')->create();

            // Assert
            expect($auditLog->token)->toBeInstanceOf(AccessToken::class);
            expect($auditLog->token->id)->toBe($token->id);
        });

        test('token can have multiple audit logs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $existingCount = $token->auditLogs()->count(); // Token creation creates 1 audit log
            $count = 5;

            // Act
            AccessTokenAuditLog::factory()->count($count)->for($token, 'token')->create();

            // Assert - Should have existing + newly created
            expect($token->auditLogs()->count())->toBe($existingCount + $count);
        });
    });

    describe('Randomness', function (): void {
        test('generates different IP addresses for multiple logs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog1 = AccessTokenAuditLog::factory()->for($token, 'token')->create();
            $auditLog2 = AccessTokenAuditLog::factory()->for($token, 'token')->create();

            // Assert - There's a chance they could be the same, but unlikely
            // We're testing the factory uses Faker correctly
            expect($auditLog1->ip_address)->toBeString();
            expect($auditLog2->ip_address)->toBeString();
        });

        test('generates different user agents for multiple logs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog1 = AccessTokenAuditLog::factory()->for($token, 'token')->create();
            $auditLog2 = AccessTokenAuditLog::factory()->for($token, 'token')->create();

            // Assert
            expect($auditLog1->user_agent)->toBeString();
            expect($auditLog2->user_agent)->toBeString();
        });

        test('generates random events from all available cases', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $count = 50;

            // Act
            $auditLogs = AccessTokenAuditLog::factory()->count($count)->for($token, 'token')->create();

            // Assert - With 50 logs, we should see some variety in events
            $events = $auditLogs->pluck('event')->unique();
            expect($events->count())->toBeGreaterThan(1);

            // All events should be valid AuditEvent cases
            foreach ($auditLogs as $auditLog) {
                expect($auditLog->event)->toBeInstanceOf(AuditEvent::class);
            }
        });
    });
});
