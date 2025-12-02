<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\AuditDrivers\SpatieActivityLogDriver;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Sleep;
use Spatie\Activitylog\Models\Activity;

describe('SpatieActivityLogDriver', function (): void {
    beforeEach(function (): void {
        // Configure Spatie activitylog
        config()->set('activitylog', [
            'enabled' => true,
            'default_auth_driver' => null,
            'default_log_name' => 'default',
            'activity_model' => Activity::class,
            'table_name' => 'activity_log',
            'database_connection' => null,
            'subject_returns_soft_deleted_models' => false,
        ]);

        // Create activity_log table
        Schema::create('activity_log', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('log_name')->nullable();
            $table->text('description');
            $table->nullableMorphs('subject', 'subject');
            $table->string('event')->nullable();
            $table->nullableMorphs('causer', 'causer');
            $table->json('properties')->nullable();
            $table->uuid('batch_uuid')->nullable();
            $table->timestamps();
            $table->index('log_name');
        });

        $this->driver = new SpatieActivityLogDriver();
        $this->user = createUser();
        $this->token = createAccessToken($this->user);
    });

    afterEach(function (): void {
        Schema::dropIfExists('activity_log');
    });

    it('implements AuditDriver contract', function (): void {
        expect($this->driver)->toBeInstanceOf(AuditDriver::class);
    });

    describe('log()', function (): void {
        it('creates activity log entry with correct log name', function (): void {
            // Arrange
            $event = AuditEvent::Created;

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            expect($activity)->not->toBeNull();
            expect($activity->log_name)->toBe('bearer');
        });

        it('records token as subject (performedOn)', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            expect($activity->subject_type)->toBe($this->token::class);
            expect($activity->subject_id)->toBe($this->token->id);
            expect($activity->subject->id)->toBe($this->token->id);
        });

        it('records owner as causer (causedBy)', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            expect($activity->causer_type)->toBe($this->user::class);
            expect($activity->causer_id)->toBe($this->user->id);
            expect($activity->causer->id)->toBe($this->user->id);
        });

        it('stores event type', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            expect($activity->event)->toBe('authenticated');
        });

        it('captures IP address in properties', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;
            request()->merge(['REMOTE_ADDR' => '192.168.1.100']);

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            $properties = $activity->properties;
            expect($properties->has('ip_address'))->toBeTrue();
        });

        it('captures user agent in properties', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;
            request()->headers->set('User-Agent', 'TestAgent/1.0');

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            $properties = $activity->properties;
            expect($properties->has('user_agent'))->toBeTrue();
            expect($properties->get('user_agent'))->toBe('TestAgent/1.0');
        });

        it('includes custom context in properties', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;
            $context = [
                'endpoint' => '/api/users',
                'method' => 'GET',
                'response_code' => 200,
            ];

            // Act
            $this->driver->log($this->token, $event, $context);

            // Assert
            $activity = Activity::query()->first();
            $properties = $activity->properties;
            expect($properties->get('endpoint'))->toBe('/api/users');
            expect($properties->get('method'))->toBe('GET');
            expect($properties->get('response_code'))->toBe(200);
        });

        it('merges custom context with request metadata', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;
            $context = [
                'custom_field' => 'custom_value',
                'request_id' => 'req_12345',
            ];
            request()->headers->set('User-Agent', 'TestAgent/2.0');

            // Act
            $this->driver->log($this->token, $event, $context);

            // Assert
            $activity = Activity::query()->first();
            $properties = $activity->properties;
            expect($properties->has('ip_address'))->toBeTrue();
            expect($properties->get('user_agent'))->toBe('TestAgent/2.0');
            expect($properties->get('custom_field'))->toBe('custom_value');
            expect($properties->get('request_id'))->toBe('req_12345');
        });

        it('creates description with event name', function (): void {
            // Arrange
            $event = AuditEvent::Authenticated;

            // Act
            $this->driver->log($this->token, $event);

            // Assert
            $activity = Activity::query()->first();
            expect($activity->description)->toBe('Token authenticated');
        });

        it('handles all AuditEvent types', function (): void {
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

            // Act
            foreach ($events as $event) {
                $this->driver->log($this->token, $event);
            }

            // Assert
            expect(Activity::query()->count())->toBe(9);

            $expectedEvents = [
                'created',
                'authenticated',
                'revoked',
                'rotated',
                'failed',
                'rate_limited',
                'ip_blocked',
                'domain_blocked',
                'expired',
            ];

            $actualEvents = Activity::query()->pluck('event')->toArray();
            expect($actualEvents)->toBe($expectedEvents);
        });

        it('creates separate log entries for multiple calls', function (): void {
            // Arrange
            $event1 = AuditEvent::Created;
            $event2 = AuditEvent::Authenticated;
            $event3 = AuditEvent::Revoked;

            // Act
            $this->driver->log($this->token, $event1);
            $this->driver->log($this->token, $event2);
            $this->driver->log($this->token, $event3);

            // Assert
            expect(Activity::query()->count())->toBe(3);
        });

        it('works with different tokens', function (): void {
            // Arrange
            $token1 = createAccessToken($this->user, 'sk', ['name' => 'Token 1']);
            $token2 = createAccessToken($this->user, 'sk', ['name' => 'Token 2']);

            // Act
            $this->driver->log($token1, AuditEvent::Created);
            $this->driver->log($token2, AuditEvent::Authenticated);

            // Assert
            expect(Activity::query()->count())->toBe(2);

            $token1Activities = Activity::query()->forSubject($token1)->get();
            $token2Activities = Activity::query()->forSubject($token2)->get();

            expect($token1Activities->count())->toBe(1);
            expect($token2Activities->count())->toBe(1);
            expect($token1Activities->first()->event)->toBe('created');
            expect($token2Activities->first()->event)->toBe('authenticated');
        });
    });

    describe('getLogsForToken()', function (): void {
        it('returns activities for the token', function (): void {
            // Arrange
            $this->driver->log($this->token, AuditEvent::Created);
            $this->driver->log($this->token, AuditEvent::Authenticated);

            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs)->toBeInstanceOf(Collection::class);
            expect($logs->count())->toBe(2);
        });

        it('filters by log name', function (): void {
            // Arrange
            $this->driver->log($this->token, AuditEvent::Created);

            // Create an activity with a different log name
            activity('different-log')
                ->performedOn($this->token)
                ->causedBy($this->user)
                ->event('other')
                ->log('Other event');

            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs->count())->toBe(1);
            expect($logs->first()->log_name)->toBe('bearer');
        });

        it('returns newest first (latest)', function (): void {
            // Arrange
            Sleep::sleep(1); // Ensure time difference
            $this->driver->log($this->token, AuditEvent::Created);
            Sleep::sleep(1);
            $this->driver->log($this->token, AuditEvent::Authenticated);
            Sleep::sleep(1);
            $this->driver->log($this->token, AuditEvent::Revoked);

            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs->count())->toBe(3);
            expect($logs->first()->event)->toBe('revoked');
            expect($logs->last()->event)->toBe('created');
        });

        it('returns only activities for the specified token', function (): void {
            // Arrange
            $token1 = createAccessToken($this->user, 'sk', ['name' => 'Token 1']);
            $token2 = createAccessToken($this->user, 'sk', ['name' => 'Token 2']);

            $this->driver->log($token1, AuditEvent::Created);
            $this->driver->log($token1, AuditEvent::Authenticated);
            $this->driver->log($token2, AuditEvent::Created);

            // Act
            $logs1 = $this->driver->getLogsForToken($token1);
            $logs2 = $this->driver->getLogsForToken($token2);

            // Assert
            expect($logs1->count())->toBe(2);
            expect($logs2->count())->toBe(1);
        });

        it('returns empty collection when no logs exist', function (): void {
            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            expect($logs)->toBeInstanceOf(Collection::class);
            expect($logs->count())->toBe(0);
            expect($logs->isEmpty())->toBeTrue();
        });

        it('includes all activity properties', function (): void {
            // Arrange
            $context = [
                'endpoint' => '/api/users',
                'method' => 'POST',
            ];
            $this->driver->log($this->token, AuditEvent::Created, $context);

            // Act
            $logs = $this->driver->getLogsForToken($this->token);

            // Assert
            $activity = $logs->first();
            expect($activity->properties->get('endpoint'))->toBe('/api/users');
            expect($activity->properties->get('method'))->toBe('POST');
        });
    });

    describe('custom log name', function (): void {
        it('uses custom log name via constructor', function (): void {
            // Arrange
            $driver = new SpatieActivityLogDriver('custom-tokens');

            // Act
            $driver->log($this->token, AuditEvent::Created);

            // Assert
            $activity = Activity::query()->first();
            expect($activity->log_name)->toBe('custom-tokens');
        });

        it('filters by custom log name in getLogsForToken', function (): void {
            // Arrange
            $driver = new SpatieActivityLogDriver('custom-tokens');
            $driver->log($this->token, AuditEvent::Created);

            // Create activity with default log name
            $defaultDriver = new SpatieActivityLogDriver();
            $defaultDriver->log($this->token, AuditEvent::Authenticated);

            // Act
            $customLogs = $driver->getLogsForToken($this->token);
            $defaultLogs = $defaultDriver->getLogsForToken($this->token);

            // Assert
            expect($customLogs->count())->toBe(1);
            expect($customLogs->first()->log_name)->toBe('custom-tokens');
            expect($defaultLogs->count())->toBe(1);
            expect($defaultLogs->first()->log_name)->toBe('bearer');
        });

        it('supports multiple log names for different token types', function (): void {
            // Arrange
            $apiDriver = new SpatieActivityLogDriver('api-tokens');
            $webDriver = new SpatieActivityLogDriver('web-tokens');

            $token1 = createAccessToken($this->user, 'sk', ['name' => 'API Token']);
            $token2 = createAccessToken($this->user, 'sk', ['name' => 'Web Token']);

            // Act
            $apiDriver->log($token1, AuditEvent::Created);
            $webDriver->log($token2, AuditEvent::Created);

            // Assert
            $apiLogs = $apiDriver->getLogsForToken($token1);
            $webLogs = $webDriver->getLogsForToken($token2);

            expect($apiLogs->count())->toBe(1);
            expect($apiLogs->first()->log_name)->toBe('api-tokens');
            expect($webLogs->count())->toBe(1);
            expect($webLogs->first()->log_name)->toBe('web-tokens');
        });
    });

    describe('integration scenarios', function (): void {
        it('tracks complete token lifecycle', function (): void {
            // Arrange & Act - simulate token lifecycle
            $this->driver->log($this->token, AuditEvent::Created, ['created_by' => 'admin']);
            $this->driver->log($this->token, AuditEvent::Authenticated, ['endpoint' => '/api/users']);
            $this->driver->log($this->token, AuditEvent::Authenticated, ['endpoint' => '/api/posts']);
            $this->driver->log($this->token, AuditEvent::RateLimited, ['limit' => 100]);
            $this->driver->log($this->token, AuditEvent::Revoked, ['revoked_by' => 'admin']);

            // Assert
            $logs = $this->driver->getLogsForToken($this->token);
            expect($logs->count())->toBe(5);

            $events = $logs->pluck('event')->toArray();
            expect($events)->toContain('created');
            expect($events)->toContain('authenticated');
            expect($events)->toContain('rate_limited');
            expect($events)->toContain('revoked');
        });

        it('maintains context across multiple authentication attempts', function (): void {
            // Arrange & Act
            $endpoints = ['/api/users', '/api/posts', '/api/comments'];

            foreach ($endpoints as $endpoint) {
                $this->driver->log($this->token, AuditEvent::Authenticated, [
                    'endpoint' => $endpoint,
                    'timestamp' => now()->toISOString(),
                ]);
            }

            // Assert
            $logs = $this->driver->getLogsForToken($this->token);
            expect($logs->count())->toBe(3);

            // Verify all endpoints are logged
            $loggedEndpoints = $logs->map(fn ($log) => $log->properties->get('endpoint'))->toArray();
            expect($loggedEndpoints)->toContain('/api/users');
            expect($loggedEndpoints)->toContain('/api/posts');
            expect($loggedEndpoints)->toContain('/api/comments');
        });

        it('works with token rotation', function (): void {
            // Arrange
            $oldToken = $this->token;
            $newToken = createAccessToken($this->user, 'sk', ['name' => 'Rotated Token']);

            // Act
            $this->driver->log($oldToken, AuditEvent::Rotated, ['new_token_id' => $newToken->id]);
            $this->driver->log($newToken, AuditEvent::Created, ['rotated_from' => $oldToken->id]);

            // Assert
            $oldLogs = $this->driver->getLogsForToken($oldToken);
            $newLogs = $this->driver->getLogsForToken($newToken);

            expect($oldLogs->count())->toBe(1);
            expect($oldLogs->first()->event)->toBe('rotated');
            expect($oldLogs->first()->properties->get('new_token_id'))->toBe($newToken->id);

            expect($newLogs->count())->toBe(1);
            expect($newLogs->first()->event)->toBe('created');
            expect($newLogs->first()->properties->get('rotated_from'))->toBe($oldToken->id);
        });
    });
});
