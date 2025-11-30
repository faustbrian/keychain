<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\BearerManager;
use Cline\Bearer\Contracts\AuditDriver;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Contracts\TokenGenerator;
use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Facades\Bearer;
use Cline\Bearer\Support\TokenComponents;
use Cline\Bearer\TokenGenerators\RandomTokenGenerator;
use Cline\Bearer\TokenTypes\AbstractTokenType;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;
use Tests\Exceptions\AuditSystemException;
use Tests\Exceptions\DatabaseConnectionException;

describe('BearerManager - Token Finding', function (): void {
    it('finds token by id|plaintext format with valid hash', function (): void {
        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test Token');

        // Create id|plaintext format token string
        $tokenString = $result->accessToken->id.'|'.$result->plainTextToken;

        // Find token using BearerManager directly
        $foundToken = Bearer::findToken($tokenString);

        expect($foundToken)->not->toBeNull();
        expect($foundToken->id)->toBe($result->accessToken->id);
        expect($foundToken->name)->toBe('Test Token');
    });

    it('returns null when id|plaintext format has invalid hash', function (): void {
        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test Token');

        // Create id|plaintext format with wrong plaintext part
        $tokenString = $result->accessToken->id.'|invalid_plaintext_token';

        $foundToken = Bearer::findToken($tokenString);

        expect($foundToken)->toBeNull();
    });

    it('returns null when id|plaintext format has non-existent id', function (): void {
        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test Token');

        // Use non-existent ID with valid plaintext
        $tokenString = '99999|'.$result->plainTextToken;

        $foundToken = Bearer::findToken($tokenString);

        expect($foundToken)->toBeNull();
    });

    it('finds token without pipe separator using hash lookup', function (): void {
        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test Token');

        // Use plain token without id prefix
        $foundToken = Bearer::findToken($result->plainTextToken);

        expect($foundToken)->not->toBeNull();
        expect($foundToken->id)->toBe($result->accessToken->id);
    });

    it('handles multiple pipe characters in token correctly', function (): void {
        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test Token');

        // Test with extra pipe characters (should only split on first pipe)
        $tokenString = $result->accessToken->id.'|'.$result->plainTextToken.'|extra|data';

        // This should still work because explode limit is 2
        $foundToken = Bearer::findToken($tokenString);

        // Should fail because the plaintext part includes |extra|data
        expect($foundToken)->toBeNull();
    });
});

describe('BearerManager - Revocation with Audit Failures', function (): void {
    it('silently continues when audit driver throws exception during revocation', function (): void {
        $user = createUser();
        $token = createToken($user);

        // Create a custom audit driver that always throws
        $failingDriver = new class() implements AuditDriver
        {
            public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                throw AuditSystemException::systemDown();
            }

            public function getLogsForToken(AccessToken $token): Collection
            {
                return new Collection();
            }
        };

        // Register the failing audit driver
        app(BearerManager::class)->registerAuditDriver('failing', $failingDriver);

        // Temporarily override config
        config(['bearer.audit.driver' => 'failing']);

        // Revoke should succeed despite audit failure
        Bearer::revoke($token)->revoke();

        // Verify token was revoked
        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($token->fresh()->revoked_at)->not->toBeNull();

        // Restore default audit driver
        config(['bearer.audit.driver' => 'database']);
    });

    it('completes revocation even when audit driver fails', function (): void {
        $user = createUser();
        $token = createToken($user);

        // Create audit driver that throws on log
        $throwingDriver = new class() implements AuditDriver
        {
            public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                throw DatabaseConnectionException::failed();
            }

            public function getLogsForToken(AccessToken $token): Collection
            {
                return new Collection();
            }
        };

        app(BearerManager::class)->registerAuditDriver('throwing', $throwingDriver);
        config(['bearer.audit.driver' => 'throwing']);

        // Should not throw exception
        expect(fn (): mixed => Bearer::revoke($token)->revoke())->not->toThrow(Exception::class);

        // Token should still be revoked
        expect($token->fresh()->isRevoked())->toBeTrue();

        config(['bearer.audit.driver' => 'database']);
    });
});

describe('BearerManager - Registration Methods', function (): void {
    it('registers custom token type', function (): void {
        $customType = new class('custom', 'ct') extends AbstractTokenType
        {
            public function key(): string
            {
                return 'custom';
            }

            public function clientSide(): bool
            {
                return false;
            }

            public function allowedDomains(): bool
            {
                return false;
            }
        };

        app(BearerManager::class)->registerTokenType('custom', $customType);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->tokenType('custom');

        expect($retrieved)->toBe($customType);
        expect($retrieved->key())->toBe('custom');
        expect($retrieved->prefix())->toBe('ct');
    });

    it('registers custom token generator', function (): void {
        $customGenerator = new class() implements TokenGenerator
        {
            public function generate(string $prefix, string $environment): string
            {
                return 'custom_generated_'.$prefix.'_'.$environment.'_'.bin2hex(random_bytes(10));
            }

            public function parse(string $token): ?TokenComponents
            {
                return null;
            }

            public function hash(string $token): string
            {
                return hash('sha256', $token);
            }

            public function verify(string $plainToken, string $hashedToken): bool
            {
                return $this->hash($plainToken) === $hashedToken;
            }
        };

        app(BearerManager::class)->registerTokenGenerator('custom', $customGenerator);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->tokenGenerator('custom');

        expect($retrieved)->toBe($customGenerator);
        expect($retrieved->generate('test', 'local'))->toStartWith('custom_generated_test_local_');
    });

    it('registers custom token hasher', function (): void {
        $customHasher = new class() implements TokenHasher
        {
            public function hash(string $token): string
            {
                return 'custom_'.hash('sha256', $token);
            }

            public function verify(string $plainToken, string $hashedToken): bool
            {
                return $this->hash($plainToken) === $hashedToken;
            }
        };

        app(BearerManager::class)->registerTokenHasher('custom', $customHasher);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->tokenHasher('custom');

        expect($retrieved)->toBe($customHasher);
        expect($retrieved->hash('test'))->toStartWith('custom_');
    });

    it('registers custom audit driver', function (): void {
        $customDriver = new class() implements AuditDriver
        {
            public array $logs = [];

            public function log(AccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                $this->logs[] = [
                    'token_id' => $token->id,
                    'event' => $event,
                    'metadata' => $metadata,
                ];
            }

            public function getLogsForToken(AccessToken $token): Collection
            {
                return new Collection(array_filter($this->logs, fn (array $log): bool => $log['token_id'] === $token->id));
            }
        };

        app(BearerManager::class)->registerAuditDriver('custom', $customDriver);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->auditDriver('custom');

        expect($retrieved)->toBe($customDriver);
        expect($retrieved->logs)->toBeArray();
    });

    it('registers custom revocation strategy', function (): void {
        $customStrategy = new class() implements RevocationStrategy
        {
            public int $revokeCount = 0;

            public function revoke(AccessToken $token): void
            {
                ++$this->revokeCount;
                $token->revoke();
            }

            public function getAffectedTokens(AccessToken $token): Collection
            {
                return new Collection([$token]);
            }
        };

        app(BearerManager::class)->registerRevocationStrategy('custom', $customStrategy);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->revocationStrategy('custom');

        expect($retrieved)->toBe($customStrategy);
        expect($retrieved->revokeCount)->toBe(0);

        // Use it
        $user = createUser();
        $token = createToken($user);
        Bearer::executeRevocation($token, 'custom');

        expect($retrieved->revokeCount)->toBe(1);
    });

    it('registers custom rotation strategy', function (): void {
        $customStrategy = new class() implements RotationStrategy
        {
            public int $rotateCount = 0;

            public function rotate(AccessToken $oldToken, AccessToken $newToken): void
            {
                ++$this->rotateCount;
                $oldToken->revoke();
            }

            public function isOldTokenValid(AccessToken $oldToken): bool
            {
                return !$oldToken->isRevoked();
            }

            public function gracePeriodMinutes(): ?int
            {
                return null;
            }
        };

        app(BearerManager::class)->registerRotationStrategy('custom', $customStrategy);

        // Verify we can retrieve it
        $retrieved = app(BearerManager::class)->rotationStrategy('custom');

        expect($retrieved)->toBe($customStrategy);
        expect($retrieved->rotateCount)->toBe(0);

        // Use it
        $user = createUser();
        $token = createToken($user);
        Bearer::rotate($token, 'custom');

        expect($retrieved->rotateCount)->toBe(1);
    });

    it('allows multiple registrations of same type', function (): void {
        $generator1 = new RandomTokenGenerator();
        $generator2 = new RandomTokenGenerator();

        app(BearerManager::class)->registerTokenGenerator('gen1', $generator1);
        app(BearerManager::class)->registerTokenGenerator('gen2', $generator2);

        expect(app(BearerManager::class)->tokenGenerator('gen1'))->toBe($generator1);
        expect(app(BearerManager::class)->tokenGenerator('gen2'))->toBe($generator2);
    });

    it('can override default implementations via registration', function (): void {
        $originalHasher = app(BearerManager::class)->tokenHasher('sha256');

        $customHasher = new class() implements TokenHasher
        {
            public function hash(string $token): string
            {
                return 'override_'.hash('sha256', $token);
            }

            public function verify(string $plainToken, string $hashedToken): bool
            {
                return $this->hash($plainToken) === $hashedToken;
            }
        };

        // Register with same name to override
        app(BearerManager::class)->registerTokenHasher('sha256', $customHasher);

        $retrieved = app(BearerManager::class)->tokenHasher('sha256');

        expect($retrieved)->toBe($customHasher);
        expect($retrieved)->not->toBe($originalHasher);
    });

    it('registered components persist across multiple calls', function (): void {
        $customType = new class('persistent', 'ps') extends AbstractTokenType
        {
            public function key(): string
            {
                return 'persistent';
            }

            public function clientSide(): bool
            {
                return false;
            }

            public function allowedDomains(): bool
            {
                return false;
            }
        };

        app(BearerManager::class)->registerTokenType('persistent', $customType);

        // Retrieve multiple times
        $first = app(BearerManager::class)->tokenType('persistent');
        $second = app(BearerManager::class)->tokenType('persistent');
        $third = app(BearerManager::class)->tokenType('persistent');

        expect($first)->toBe($customType);
        expect($second)->toBe($customType);
        expect($third)->toBe($customType);
    });
});

describe('BearerManager - Integration with Registered Components', function (): void {
    it('uses registered token generator for token issuance', function (): void {
        $testMarker = 'CUSTOM_'.Date::now()->getTimestamp();

        $customGenerator = new readonly class($testMarker) implements TokenGenerator
        {
            public function __construct(
                private string $marker,
            ) {}

            public function generate(string $prefix, string $environment): string
            {
                return $prefix.'_'.$environment.'_'.$this->marker.'_'.bin2hex(random_bytes(20));
            }

            public function parse(string $token): ?TokenComponents
            {
                return null;
            }

            public function hash(string $token): string
            {
                return hash('sha256', $token);
            }

            public function verify(string $plainToken, string $hashedToken): bool
            {
                return $this->hash($plainToken) === $hashedToken;
            }
        };

        app(BearerManager::class)->registerTokenGenerator('test_custom', $customGenerator);

        // Temporarily change default generator
        config(['bearer.generator.default' => 'test_custom']);

        $user = createUser();
        $result = Bearer::for($user)->issue('sk', 'Test with Custom Generator');

        // Restore default
        config(['bearer.generator.default' => 'seam']);

        // Token should use custom generator (though it's hashed in DB)
        expect($result->plainTextToken)->toContain($testMarker);
    });

    it('uses registered revocation strategy in revoke operation', function (): void {
        $callLog = [];

        $loggingStrategy = new class($callLog) implements RevocationStrategy
        {
            public function __construct(
                private array &$log,
            ) {}

            public function revoke(AccessToken $token): void
            {
                $this->log[] = 'revoked_token_'.$token->id;
                $token->revoke();
            }

            public function getAffectedTokens(AccessToken $token): Collection
            {
                return new Collection([$token]);
            }
        };

        app(BearerManager::class)->registerRevocationStrategy('logging', $loggingStrategy);

        $user = createUser();
        $token = createToken($user);

        Bearer::executeRevocation($token, 'logging');

        expect($callLog)->toContain('revoked_token_'.$token->id);
        expect($token->fresh()->isRevoked())->toBeTrue();
    });

    it('uses registered rotation strategy in rotate operation', function (): void {
        $callLog = [];

        $loggingStrategy = new class($callLog) implements RotationStrategy
        {
            public function __construct(
                private array &$log,
            ) {}

            public function rotate(AccessToken $oldToken, AccessToken $newToken): void
            {
                $this->log[] = 'rotated_'.$oldToken->id.'_to_'.$newToken->id;
                $oldToken->revoke();
            }

            public function isOldTokenValid(AccessToken $oldToken): bool
            {
                return !$oldToken->isRevoked();
            }

            public function gracePeriodMinutes(): ?int
            {
                return null;
            }
        };

        app(BearerManager::class)->registerRotationStrategy('logging', $loggingStrategy);

        $user = createUser();
        $token = createToken($user);
        $oldId = $token->id;

        $newToken = Bearer::rotate($token, 'logging');

        expect($callLog)->toHaveCount(1);
        expect($callLog[0])->toContain('rotated_'.$oldId.'_to_'.$newToken->accessToken->id);
    });
});
