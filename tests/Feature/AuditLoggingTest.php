<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Facades\Bearer;

describe('Audit Logging', function (): void {
    it('logs token creation event', function (): void {
        $user = createUser();

        $token = Bearer::for($user)->issue('sk', 'API Key');

        $auditLog = AccessTokenAuditLog::query()->where('token_id', $token->accessToken->id)
            ->where('event', AuditEvent::Created)
            ->first();

        expect($auditLog)->not->toBeNull();
        expect($auditLog->event)->toBe(AuditEvent::Created);
        expect($auditLog->token_id)->toBe($token->accessToken->id);
    });

    it('stores audit log metadata', function (): void {
        $user = createUser();
        $token = Bearer::for($user)
            ->metadata(['app' => 'mobile'])
            ->issue('sk', 'Mobile Key');

        $auditLog = AccessTokenAuditLog::query()->where('token_id', $token->accessToken->id)->first();

        expect($auditLog->created_at)->not->toBeNull();
    });

    it('links audit log to token', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'Test Key');

        $auditLog = AccessTokenAuditLog::query()->where('token_id', $token->accessToken->id)->first();

        expect($auditLog->token)->not->toBeNull();
        expect($auditLog->token->id)->toBe($token->accessToken->id);
    });

    it('retrieves audit logs from token', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'Test Key');

        $auditLogs = $token->accessToken->auditLogs;

        expect($auditLogs)->not->toBeEmpty();
        expect($auditLogs->first()->event)->toBe(AuditEvent::Created);
    });

    it('filters audit logs by event type', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'Test Key');

        $createdLogs = AccessTokenAuditLog::query()->where('event', AuditEvent::Created)->get();

        expect($createdLogs)->not->toBeEmpty();
        expect($createdLogs->every(fn ($log): bool => $log->event === AuditEvent::Created))->toBeTrue();
    });

    it('records timestamp for audit events', function (): void {
        $user = createUser();
        $beforeCreation = now()->subSecond();

        $token = Bearer::for($user)->issue('sk', 'Test Key');

        $auditLog = AccessTokenAuditLog::query()->where('token_id', $token->accessToken->id)->first();

        expect($auditLog->created_at)->toBeGreaterThanOrEqual($beforeCreation);
        expect($auditLog->created_at)->toBeLessThanOrEqual(now()->addSecond());
    });

    it('maintains audit trail through token lifecycle', function (): void {
        $user = createUser();
        $token = Bearer::for($user)->issue('sk', 'Test Key');

        $initialAuditCount = AccessTokenAuditLog::query()->where('token_id', $token->accessToken->id)->count();

        expect($initialAuditCount)->toBeGreaterThan(0);
    });

    it('supports multiple audit events for same token', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'TestAgent/1.0',
        ]);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::RateLimited,
            'ip_address' => '192.168.1.1',
            'user_agent' => 'TestAgent/1.0',
        ]);

        $auditLogs = $token->auditLogs;

        expect($auditLogs->count())->toBeGreaterThanOrEqual(2);
    });

    it('stores ip address in audit log', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $auditLog = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'ip_address' => '192.168.1.100',
            'user_agent' => 'TestAgent/1.0',
        ]);

        expect($auditLog->ip_address)->toBe('192.168.1.100');
    });

    it('stores user agent in audit log', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $auditLog = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'ip_address' => '127.0.0.1',
            'user_agent' => 'Mozilla/5.0 TestBrowser',
        ]);

        expect($auditLog->user_agent)->toBe('Mozilla/5.0 TestBrowser');
    });

    it('stores custom metadata in audit log', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $metadata = [
            'action' => 'user_login',
            'endpoint' => '/api/users',
            'response_time' => 145,
        ];

        $auditLog = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'metadata' => $metadata,
        ]);

        expect($auditLog->metadata)->toBe($metadata);
        expect($auditLog->metadata['action'])->toBe('user_login');
        expect($auditLog->metadata['response_time'])->toBe(145);
    });

    it('queries audit logs by date range', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $startDate = now()->subDay();
        $endDate = now()->addDay();

        $auditLog = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now(),
        ]);

        $logs = AccessTokenAuditLog::query()->whereBetween('created_at', [$startDate, $endDate])->get();

        expect($logs->pluck('id'))->toContain($auditLog->id);
    });

    it('retrieves audit logs for specific token', function (): void {
        $user = createUser();
        $token1 = createAccessToken($user, 'sk', ['name' => 'Token 1']);
        $token2 = createAccessToken($user, 'sk', ['name' => 'Token 2']);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token2->id,
            'event' => AuditEvent::Authenticated,
        ]);

        $token2Logs = AccessTokenAuditLog::query()->where('token_id', $token2->id)->get();

        expect($token2Logs->every(fn ($log): bool => $log->token_id === $token2->id))->toBeTrue();
    });

    it('counts audit events by type', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        AccessTokenAuditLog::query()->create(['token_id' => $token->id, 'event' => AuditEvent::Authenticated]);
        AccessTokenAuditLog::query()->create(['token_id' => $token->id, 'event' => AuditEvent::Authenticated]);
        AccessTokenAuditLog::query()->create(['token_id' => $token->id, 'event' => AuditEvent::RateLimited]);

        $authCount = AccessTokenAuditLog::query()->where('token_id', $token->id)
            ->where('event', AuditEvent::Authenticated)
            ->count();

        expect($authCount)->toBe(2);
    });

    it('orders audit logs chronologically', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $log1 = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subHours(2),
        ]);

        $log2 = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::RateLimited,
            'created_at' => now()->subHour(),
        ]);

        $logs = AccessTokenAuditLog::query()
            ->where('token_id', $token->id)
            ->whereIn('event', [AuditEvent::Authenticated, AuditEvent::RateLimited])
            ->oldest('created_at')
            ->get();

        expect($logs->first()->id)->toBe($log1->id);
        expect($logs->last()->id)->toBe($log2->id);
    });

    it('retrieves latest audit log for token', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
            'created_at' => now()->subHour(),
        ]);

        $latest = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::RateLimited,
            'created_at' => now(),
        ]);

        $latestLog = AccessTokenAuditLog::query()
            ->where('token_id', $token->id)
            ->whereIn('event', [AuditEvent::Authenticated, AuditEvent::RateLimited])
            ->latest('created_at')
            ->first();

        expect($latestLog->id)->toBe($latest->id);
    });

    it('supports all audit event types', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

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

        foreach ($events as $event) {
            $log = AccessTokenAuditLog::query()->create([
                'token_id' => $token->id,
                'event' => $event,
            ]);

            expect($log->event)->toBe($event);
        }
    });

    it('casts audit event to enum', function (): void {
        $user = createUser();
        $token = createAccessToken($user);

        $log = AccessTokenAuditLog::query()->create([
            'token_id' => $token->id,
            'event' => AuditEvent::Authenticated,
        ]);

        expect($log->event)->toBeInstanceOf(AuditEvent::class);
        expect($log->event->value)->toBe('authenticated');
    });
});
