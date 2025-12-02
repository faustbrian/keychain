<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Enums\RevocationMode;
use Cline\Bearer\Enums\RotationMode;
use Cline\Bearer\Events\AccessTokenGroupCreated;
use Cline\Bearer\Events\TokenAuthenticationFailed;
use Cline\Bearer\Events\TokenCreated;
use Cline\Bearer\Events\TokenRevoked;
use Cline\Bearer\Events\TokenRotated;
use Cline\Bearer\NewAccessToken;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;

describe('TokenCreated Event', function (): void {
    it('can instantiate with required parameters', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $tokenType = 'sk';
        $environment = 'production';

        // Act
        $event = new TokenCreated(
            token: $token,
            tokenType: $tokenType,
            environment: $environment,
        );

        // Assert
        expect($event)->toBeInstanceOf(TokenCreated::class)
            ->and($event->token)->toBe($token)
            ->and($event->tokenType)->toBe($tokenType)
            ->and($event->environment)->toBe($environment);
    });

    it('has publicly accessible token property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'pk');

        // Act
        $event = new TokenCreated($token, 'pk', 'test');

        // Assert
        expect($event->token)
            ->toBeInstanceOf(AccessToken::class)
            ->toBe($token);
    });

    it('has publicly accessible tokenType property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'rk');
        $tokenType = 'restricted_key';

        // Act
        $event = new TokenCreated($token, $tokenType, 'development');

        // Assert
        expect($event->tokenType)->toBe($tokenType);
    });

    it('has publicly accessible environment property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $environment = 'staging';

        // Act
        $event = new TokenCreated($token, 'sk', $environment);

        // Assert
        expect($event->environment)->toBe($environment);
    });

    it('works with different token types', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'pk');

        // Act
        $event = new TokenCreated($token, 'publishable_key', 'production');

        // Assert
        expect($event->token)->toBeInstanceOf(AccessToken::class)
            ->and($event->tokenType)->toBe('publishable_key')
            ->and($event->environment)->toBe('production');
    });
});

describe('AccessTokenGroupCreated Event', function (): void {
    it('can instantiate with required parameters', function (): void {
        // Arrange
        $user = createUser();
        $group = $user->accessTokenGroups()->create(['name' => 'Test Group']);

        $token1 = createAccessToken($user, 'sk');
        $token2 = createAccessToken($user, 'pk');

        $newToken1 = new NewAccessToken($token1, 'sk_test_1234');
        $newToken2 = new NewAccessToken($token2, 'pk_test_5678');

        $tokens = new Collection([$newToken1, $newToken2]);

        // Act
        $event = new AccessTokenGroupCreated(
            group: $group,
            tokens: $tokens,
        );

        // Assert
        expect($event)->toBeInstanceOf(AccessTokenGroupCreated::class)
            ->and($event->group)->toBe($group)
            ->and($event->tokens)->toBe($tokens);
    });

    it('has publicly accessible group property', function (): void {
        // Arrange
        $user = createUser();
        $group = $user->accessTokenGroups()->create(['name' => 'API Group']);

        $tokens = new Collection();

        // Act
        $event = new AccessTokenGroupCreated($group, $tokens);

        // Assert
        expect($event->group)
            ->toBeInstanceOf(AccessTokenGroup::class)
            ->toBe($group);
    });

    it('has publicly accessible tokens property', function (): void {
        // Arrange
        $user = createUser();
        $group = $user->accessTokenGroups()->create(['name' => 'Service Group']);

        $token = createAccessToken($user, 'sk');
        $newToken = new NewAccessToken($token, 'sk_test_abcd');
        $tokens = new Collection([$newToken]);

        // Act
        $event = new AccessTokenGroupCreated($group, $tokens);

        // Assert
        expect($event->tokens)
            ->toBeInstanceOf(Collection::class)
            ->toBe($tokens)
            ->toHaveCount(1);
    });

    it('works with empty token collection', function (): void {
        // Arrange
        $user = createUser();
        $group = $user->accessTokenGroups()->create(['name' => 'Empty Group']);

        $tokens = new Collection();

        // Act
        $event = new AccessTokenGroupCreated($group, $tokens);

        // Assert
        expect($event->group)->toBeInstanceOf(AccessTokenGroup::class)
            ->and($event->tokens)->toBeInstanceOf(Collection::class)
            ->and($event->tokens)->toBeEmpty();
    });

    it('works with multiple tokens in collection', function (): void {
        // Arrange
        $user = createUser();
        $group = $user->accessTokenGroups()->create(['name' => 'Multi Token Group']);

        $token1 = createAccessToken($user, 'sk');
        $token2 = createAccessToken($user, 'pk');
        $token3 = createAccessToken($user, 'rk');

        $tokens = new Collection([
            new NewAccessToken($token1, 'sk_test_1'),
            new NewAccessToken($token2, 'pk_test_2'),
            new NewAccessToken($token3, 'rk_test_3'),
        ]);

        // Act
        $event = new AccessTokenGroupCreated($group, $tokens);

        // Assert
        expect($event->tokens)->toHaveCount(3);
    });
});

describe('TokenRevoked Event', function (): void {
    it('can instantiate with required parameters', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $mode = RevocationMode::None;

        // Act
        $event = new TokenRevoked(
            token: $token,
            mode: $mode,
        );

        // Assert
        expect($event)->toBeInstanceOf(TokenRevoked::class)
            ->and($event->token)->toBe($token)
            ->and($event->mode)->toBe($mode)
            ->and($event->reason)->toBeNull();
    });

    it('can instantiate with optional reason parameter', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $mode = RevocationMode::Cascade;
        $reason = 'User requested revocation';

        // Act
        $event = new TokenRevoked(
            token: $token,
            mode: $mode,
            reason: $reason,
        );

        // Assert
        expect($event)->toBeInstanceOf(TokenRevoked::class)
            ->and($event->token)->toBe($token)
            ->and($event->mode)->toBe($mode)
            ->and($event->reason)->toBe($reason);
    });

    it('has publicly accessible token property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'pk');

        // Act
        $event = new TokenRevoked($token, RevocationMode::None);

        // Assert
        expect($event->token)
            ->toBeInstanceOf(AccessToken::class)
            ->toBe($token);
    });

    it('has publicly accessible mode property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $mode = RevocationMode::Partial;

        // Act
        $event = new TokenRevoked($token, $mode);

        // Assert
        expect($event->mode)->toBe($mode);
    });

    it('has publicly accessible reason property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = 'Security breach detected';

        // Act
        $event = new TokenRevoked($token, RevocationMode::Cascade, $reason);

        // Assert
        expect($event->reason)->toBe($reason);
    });

    it('works with different revocation modes', function (RevocationMode $mode): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');

        // Act
        $event = new TokenRevoked($token, $mode, 'Test revocation');

        // Assert
        expect($event->mode)->toBe($mode);
    })->with([
        'none mode' => [RevocationMode::None],
        'cascade mode' => [RevocationMode::Cascade],
        'partial mode' => [RevocationMode::Partial],
        'timed mode' => [RevocationMode::Timed],
    ]);

    it('defaults reason to null when not provided', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');

        // Act
        $event = new TokenRevoked($token, RevocationMode::None);

        // Assert
        expect($event->reason)->toBeNull();
    });
});

describe('TokenRotated Event', function (): void {
    it('can instantiate with required parameters', function (): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old Token']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New Token']);
        $mode = RotationMode::Immediate;

        // Act
        $event = new TokenRotated(
            oldToken: $oldToken,
            newToken: $newToken,
            mode: $mode,
        );

        // Assert
        expect($event)->toBeInstanceOf(TokenRotated::class)
            ->and($event->oldToken)->toBe($oldToken)
            ->and($event->newToken)->toBe($newToken)
            ->and($event->mode)->toBe($mode);
    });

    it('has publicly accessible oldToken property', function (): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New']);

        // Act
        $event = new TokenRotated($oldToken, $newToken, RotationMode::Immediate);

        // Assert
        expect($event->oldToken)
            ->toBeInstanceOf(AccessToken::class)
            ->toBe($oldToken);
    });

    it('has publicly accessible newToken property', function (): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New']);

        // Act
        $event = new TokenRotated($oldToken, $newToken, RotationMode::GracePeriod);

        // Assert
        expect($event->newToken)
            ->toBeInstanceOf(AccessToken::class)
            ->toBe($newToken);
    });

    it('has publicly accessible mode property', function (): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New']);
        $mode = RotationMode::DualValid;

        // Act
        $event = new TokenRotated($oldToken, $newToken, $mode);

        // Assert
        expect($event->mode)->toBe($mode);
    });

    it('works with different rotation modes', function (RotationMode $mode): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New']);

        // Act
        $event = new TokenRotated($oldToken, $newToken, $mode);

        // Assert
        expect($event->mode)->toBe($mode);
    })->with([
        'immediate mode' => [RotationMode::Immediate],
        'grace period mode' => [RotationMode::GracePeriod],
        'dual valid mode' => [RotationMode::DualValid],
    ]);

    it('distinguishes between old and new tokens', function (): void {
        // Arrange
        $user = createUser();
        $oldToken = createAccessToken($user, 'sk', ['name' => 'Old Token']);
        $newToken = createAccessToken($user, 'sk', ['name' => 'New Token']);

        // Act
        $event = new TokenRotated($oldToken, $newToken, RotationMode::Immediate);

        // Assert
        expect($event->oldToken)->not->toBe($event->newToken)
            ->and($event->oldToken->name)->toBe('Old Token')
            ->and($event->newToken->name)->toBe('New Token');
    });
});

describe('TokenAuthenticationFailed Event', function (): void {
    it('can instantiate with required parameters', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = AuditEvent::Failed;

        // Act
        $event = new TokenAuthenticationFailed(
            token: $token,
            reason: $reason,
        );

        // Assert
        expect($event)->toBeInstanceOf(TokenAuthenticationFailed::class)
            ->and($event->token)->toBe($token)
            ->and($event->reason)->toBe($reason)
            ->and($event->ipAddress)->toBeNull()
            ->and($event->context)->toBeEmpty();
    });

    it('can instantiate with null token', function (): void {
        // Arrange
        $reason = AuditEvent::Failed;

        // Act
        $event = new TokenAuthenticationFailed(
            token: null,
            reason: $reason,
        );

        // Assert
        expect($event->token)->toBeNull()
            ->and($event->reason)->toBe($reason);
    });

    it('can instantiate with optional ipAddress parameter', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = AuditEvent::RateLimited;
        $ipAddress = '192.168.1.100';

        // Act
        $event = new TokenAuthenticationFailed(
            token: $token,
            reason: $reason,
            ipAddress: $ipAddress,
        );

        // Assert
        expect($event->ipAddress)->toBe($ipAddress);
    });

    it('can instantiate with optional context parameter', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = AuditEvent::IpBlocked;
        $context = ['user_agent' => 'Mozilla/5.0', 'endpoint' => '/api/users'];

        // Act
        $event = new TokenAuthenticationFailed(
            token: $token,
            reason: $reason,
            ipAddress: null,
            context: $context,
        );

        // Assert
        expect($event->context)->toBe($context)
            ->toHaveKey('user_agent')
            ->toHaveKey('endpoint');
    });

    it('can instantiate with all parameters', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = AuditEvent::Expired;
        $ipAddress = '10.0.0.1';
        $context = ['attempt' => 3, 'location' => 'US'];

        // Act
        $event = new TokenAuthenticationFailed(
            token: $token,
            reason: $reason,
            ipAddress: $ipAddress,
            context: $context,
        );

        // Assert
        expect($event->token)->toBe($token)
            ->and($event->reason)->toBe($reason)
            ->and($event->ipAddress)->toBe($ipAddress)
            ->and($event->context)->toBe($context);
    });

    it('has publicly accessible token property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'pk');

        // Act
        $event = new TokenAuthenticationFailed($token, AuditEvent::Failed);

        // Assert
        expect($event->token)
            ->toBeInstanceOf(AccessToken::class)
            ->toBe($token);
    });

    it('has publicly accessible reason property', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');
        $reason = AuditEvent::DomainBlocked;

        // Act
        $event = new TokenAuthenticationFailed($token, $reason);

        // Assert
        expect($event->reason)->toBe($reason);
    });

    it('has publicly accessible ipAddress property', function (): void {
        // Arrange
        $ipAddress = '172.16.0.1';

        // Act
        $event = new TokenAuthenticationFailed(null, AuditEvent::Failed, $ipAddress);

        // Assert
        expect($event->ipAddress)->toBe($ipAddress);
    });

    it('has publicly accessible context property', function (): void {
        // Arrange
        $context = ['error' => 'Invalid signature', 'timestamp' => Date::now()->getTimestamp()];

        // Act
        $event = new TokenAuthenticationFailed(null, AuditEvent::Failed, null, $context);

        // Assert
        expect($event->context)->toBe($context);
    });

    it('works with different audit event reasons', function (AuditEvent $reason): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');

        // Act
        $event = new TokenAuthenticationFailed($token, $reason);

        // Assert
        expect($event->reason)->toBe($reason);
    })->with([
        'failed' => [AuditEvent::Failed],
        'rate limited' => [AuditEvent::RateLimited],
        'ip blocked' => [AuditEvent::IpBlocked],
        'domain blocked' => [AuditEvent::DomainBlocked],
        'expired' => [AuditEvent::Expired],
    ]);

    it('defaults ipAddress to null when not provided', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');

        // Act
        $event = new TokenAuthenticationFailed($token, AuditEvent::Failed);

        // Assert
        expect($event->ipAddress)->toBeNull();
    });

    it('defaults context to empty array when not provided', function (): void {
        // Arrange
        $user = createUser();
        $token = createAccessToken($user, 'sk');

        // Act
        $event = new TokenAuthenticationFailed($token, AuditEvent::Failed);

        // Assert
        expect($event->context)
            ->toBeArray()
            ->toBeEmpty();
    });

    it('handles complex context data', function (): void {
        // Arrange
        $context = [
            'request' => [
                'method' => 'POST',
                'path' => '/api/tokens',
                'headers' => ['Authorization' => 'Bearer ***'],
            ],
            'metadata' => [
                'attempts' => 5,
                'last_attempt_at' => now()->toISOString(),
            ],
        ];

        // Act
        $event = new TokenAuthenticationFailed(null, AuditEvent::Failed, '10.0.0.1', $context);

        // Assert
        expect($event->context)
            ->toHaveKey('request')
            ->toHaveKey('metadata')
            ->and($event->context['request'])->toHaveKey('method')
            ->and($event->context['metadata'])->toHaveKey('attempts');
    });
});
