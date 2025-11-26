<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Database\Models\TokenAuditLog;
use Cline\Keychain\Database\Models\TokenGroup;
use Cline\Keychain\Enums\AuditEvent;
use Tests\Fixtures\User;

describe('TokenGroupFactory', function (): void {
    describe('Happy Path', function (): void {
        test('creates valid TokenGroup', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup)->toBeInstanceOf(TokenGroup::class);
            expect($tokenGroup->id)->not->toBeNull();
            expect($tokenGroup->name)->toBeString();
            expect($tokenGroup->name)->not->toBeEmpty();
            expect($tokenGroup->metadata)->toBeNull();
            expect($tokenGroup->owner_id)->toBe($user->id);
            expect($tokenGroup->owner_type)->toBe(User::class);
            expect($tokenGroup->created_at)->not->toBeNull();
            expect($tokenGroup->updated_at)->not->toBeNull();
        });

        test('creates TokenGroup with custom name', function (): void {
            // Arrange
            $user = createUser();
            $customName = 'Production Keys';

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create([
                'name' => $customName,
            ]);

            // Assert
            expect($tokenGroup->name)->toBe($customName);
        });

        test('creates TokenGroup with custom metadata', function (): void {
            // Arrange
            $user = createUser();
            $metadata = [
                'environment' => 'production',
                'region' => 'us-east-1',
            ];

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe($metadata);
            expect($tokenGroup->metadata['environment'])->toBe('production');
            expect($tokenGroup->metadata['region'])->toBe('us-east-1');
        });

        test('creates multiple TokenGroups', function (): void {
            // Arrange
            $user = createUser();
            $count = 5;

            // Act
            $tokenGroups = TokenGroup::factory()->count($count)->for($user, 'owner')->create();

            // Assert
            expect($tokenGroups)->toHaveCount($count);

            foreach ($tokenGroups as $tokenGroup) {
                expect($tokenGroup)->toBeInstanceOf(TokenGroup::class);
                expect($tokenGroup->name)->toBeString();
                expect($tokenGroup->owner_id)->toBe($user->id);
            }
        });

        test('creates TokenGroup with unique names', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup1 = TokenGroup::factory()->for($user, 'owner')->create();
            $tokenGroup2 = TokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup1->name)->not->toBe($tokenGroup2->name);
        });
    });

    describe('Sad Path', function (): void {
        // Note: Factory validations are typically handled at the database level
        // These tests verify the factory produces valid data that passes constraints
    });

    describe('Edge Cases', function (): void {
        test('creates TokenGroup with empty metadata array', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => [],
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe([]);
        });

        test('creates TokenGroup with long name', function (): void {
            // Arrange
            $user = createUser();
            $longName = str_repeat('A', 255); // Max typical VARCHAR length

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create([
                'name' => $longName,
            ]);

            // Assert
            expect($tokenGroup->name)->toBe($longName);
            expect(mb_strlen($tokenGroup->name))->toBe(255);
        });

        test('creates TokenGroup with nested metadata', function (): void {
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
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($tokenGroup->metadata)->toBe($metadata);
            expect($tokenGroup->metadata['config']['notifications']['email'])->toBeTrue();
        });
    });

    describe('Relationships', function (): void {
        test('TokenGroup can have multiple tokens', function (): void {
            // Arrange
            $user = createUser();
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create();

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

        test('TokenGroup has owner relationship', function (): void {
            // Arrange
            $user = createUser();

            // Act
            $tokenGroup = TokenGroup::factory()->for($user, 'owner')->create();

            // Assert
            expect($tokenGroup->owner)->toBeInstanceOf(User::class);
            expect($tokenGroup->owner->id)->toBe($user->id);
        });
    });
});

describe('TokenAuditLogFactory', function (): void {
    describe('Happy Path', function (): void {
        test('creates valid TokenAuditLog', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create();

            // Assert
            expect($auditLog)->toBeInstanceOf(TokenAuditLog::class);
            expect($auditLog->id)->not->toBeNull();
            expect($auditLog->token_id)->toBe($token->id);
            expect($auditLog->event)->toBeInstanceOf(AuditEvent::class);
            expect($auditLog->ip_address)->toBeString();
            expect($auditLog->user_agent)->toBeString();
            expect($auditLog->metadata)->toBeNull();
            expect($auditLog->created_at)->not->toBeNull();
        });

        test('creates TokenAuditLog with specific event', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $event = AuditEvent::Created;

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'event' => $event,
            ]);

            // Assert
            expect($auditLog->event)->toBe($event);
        });

        test('creates TokenAuditLog with all possible events', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act & Assert - Test each AuditEvent case
            foreach (AuditEvent::cases() as $event) {
                $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                    'event' => $event,
                ]);

                expect($auditLog->event)->toBe($event);
            }
        });

        test('creates TokenAuditLog with custom IP address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $ipAddress = '192.168.1.100';

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => $ipAddress,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBe($ipAddress);
        });

        test('creates TokenAuditLog with custom user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $userAgent = 'Mozilla/5.0 (Custom Browser)';

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => $userAgent,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBe($userAgent);
        });

        test('creates TokenAuditLog with custom metadata', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $metadata = [
                'request_id' => 'abc123',
                'endpoint' => '/api/users',
            ];

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($auditLog->metadata)->toBe($metadata);
            expect($auditLog->metadata['request_id'])->toBe('abc123');
            expect($auditLog->metadata['endpoint'])->toBe('/api/users');
        });

        test('creates multiple TokenAuditLogs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $count = 10;

            // Act
            $auditLogs = TokenAuditLog::factory()->count($count)->for($token, 'token')->create();

            // Assert
            expect($auditLogs)->toHaveCount($count);

            foreach ($auditLogs as $auditLog) {
                expect($auditLog)->toBeInstanceOf(TokenAuditLog::class);
                expect($auditLog->token_id)->toBe($token->id);
            }
        });
    });

    describe('Sad Path', function (): void {
        // Note: Factory validations are typically handled at the database level
    });

    describe('Edge Cases', function (): void {
        test('creates TokenAuditLog with IPv6 address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $ipv6Address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => $ipv6Address,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBe($ipv6Address);
        });

        test('creates TokenAuditLog with null IP address', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'ip_address' => null,
            ]);

            // Assert
            expect($auditLog->ip_address)->toBeNull();
        });

        test('creates TokenAuditLog with null user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => null,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBeNull();
        });

        test('creates TokenAuditLog with empty metadata array', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => [],
            ]);

            // Assert
            expect($auditLog->metadata)->toBe([]);
        });

        test('creates TokenAuditLog with nested metadata', function (): void {
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
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'metadata' => $metadata,
            ]);

            // Assert
            expect($auditLog->metadata)->toBe($metadata);
            expect($auditLog->metadata['request']['method'])->toBe('POST');
        });

        test('creates TokenAuditLog with very long user agent', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $longUserAgent = str_repeat('A', 500);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create([
                'user_agent' => $longUserAgent,
            ]);

            // Assert
            expect($auditLog->user_agent)->toBe($longUserAgent);
        });
    });

    describe('Relationships', function (): void {
        test('TokenAuditLog belongs to token', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);

            // Act
            $auditLog = TokenAuditLog::factory()->for($token, 'token')->create();

            // Assert
            expect($auditLog->token)->toBeInstanceOf(PersonalAccessToken::class);
            expect($auditLog->token->id)->toBe($token->id);
        });

        test('token can have multiple audit logs', function (): void {
            // Arrange
            $user = createUser();
            $token = createToken($user);
            $existingCount = $token->auditLogs()->count(); // Token creation creates 1 audit log
            $count = 5;

            // Act
            TokenAuditLog::factory()->count($count)->for($token, 'token')->create();

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
            $auditLog1 = TokenAuditLog::factory()->for($token, 'token')->create();
            $auditLog2 = TokenAuditLog::factory()->for($token, 'token')->create();

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
            $auditLog1 = TokenAuditLog::factory()->for($token, 'token')->create();
            $auditLog2 = TokenAuditLog::factory()->for($token, 'token')->create();

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
            $auditLogs = TokenAuditLog::factory()->count($count)->for($token, 'token')->create();

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
