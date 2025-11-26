<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Keychain\Contracts\AuditDriver;
use Cline\Keychain\Contracts\RevocationStrategy;
use Cline\Keychain\Contracts\RotationStrategy;
use Cline\Keychain\Contracts\TokenGenerator;
use Cline\Keychain\Contracts\TokenHasher;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Enums\AuditEvent;
use Cline\Keychain\Facades\Keychain;
use Cline\Keychain\KeychainManager;
use Cline\Keychain\Support\TokenComponents;
use Cline\Keychain\TokenGenerators\RandomTokenGenerator;
use Cline\Keychain\TokenTypes\AbstractTokenType;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Date;

describe('KeychainManager - Token Finding', function (): void {
    it('finds token by id|plaintext format with valid hash', function (): void {
        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test Token');

        // Create id|plaintext format token string
        $tokenString = $result->accessToken->id.'|'.$result->plainTextToken;

        // Find token using KeychainManager directly
        $foundToken = Keychain::findToken($tokenString);

        expect($foundToken)->not->toBeNull();
        expect($foundToken->id)->toBe($result->accessToken->id);
        expect($foundToken->name)->toBe('Test Token');
    });

    it('returns null when id|plaintext format has invalid hash', function (): void {
        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test Token');

        // Create id|plaintext format with wrong plaintext part
        $tokenString = $result->accessToken->id.'|invalid_plaintext_token';

        $foundToken = Keychain::findToken($tokenString);

        expect($foundToken)->toBeNull();
    });

    it('returns null when id|plaintext format has non-existent id', function (): void {
        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test Token');

        // Use non-existent ID with valid plaintext
        $tokenString = '99999|'.$result->plainTextToken;

        $foundToken = Keychain::findToken($tokenString);

        expect($foundToken)->toBeNull();
    });

    it('finds token without pipe separator using hash lookup', function (): void {
        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test Token');

        // Use plain token without id prefix
        $foundToken = Keychain::findToken($result->plainTextToken);

        expect($foundToken)->not->toBeNull();
        expect($foundToken->id)->toBe($result->accessToken->id);
    });

    it('handles multiple pipe characters in token correctly', function (): void {
        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test Token');

        // Test with extra pipe characters (should only split on first pipe)
        $tokenString = $result->accessToken->id.'|'.$result->plainTextToken.'|extra|data';

        // This should still work because explode limit is 2
        $foundToken = Keychain::findToken($tokenString);

        // Should fail because the plaintext part includes |extra|data
        expect($foundToken)->toBeNull();
    });
});

describe('KeychainManager - Revocation with Audit Failures', function (): void {
    it('silently continues when audit driver throws exception during revocation', function (): void {
        $user = createUser();
        $token = createToken($user);

        // Create a custom audit driver that always throws
        $failingDriver = new class() implements AuditDriver
        {
            public function log(PersonalAccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                throw new Exception('Audit system is down');
            }

            public function getLogsForToken(PersonalAccessToken $token): Collection
            {
                return new Collection();
            }
        };

        // Register the failing audit driver
        app(KeychainManager::class)->registerAuditDriver('failing', $failingDriver);

        // Temporarily override config
        config(['keychain.audit.driver' => 'failing']);

        // Revoke should succeed despite audit failure
        Keychain::revoke($token);

        // Verify token was revoked
        expect($token->fresh()->isRevoked())->toBeTrue();
        expect($token->fresh()->revoked_at)->not->toBeNull();

        // Restore default audit driver
        config(['keychain.audit.driver' => 'database']);
    });

    it('completes revocation even when audit driver fails', function (): void {
        $user = createUser();
        $token = createToken($user);

        // Create audit driver that throws on log
        $throwingDriver = new class() implements AuditDriver
        {
            public function log(PersonalAccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                throw new RuntimeException('Database connection failed');
            }

            public function getLogsForToken(PersonalAccessToken $token): Collection
            {
                return new Collection();
            }
        };

        app(KeychainManager::class)->registerAuditDriver('throwing', $throwingDriver);
        config(['keychain.audit.driver' => 'throwing']);

        // Should not throw exception
        expect(fn (): mixed => Keychain::revoke($token))->not->toThrow(Exception::class);

        // Token should still be revoked
        expect($token->fresh()->isRevoked())->toBeTrue();

        config(['keychain.audit.driver' => 'database']);
    });
});

describe('KeychainManager - Registration Methods', function (): void {
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

        app(KeychainManager::class)->registerTokenType('custom', $customType);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->tokenType('custom');

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

        app(KeychainManager::class)->registerTokenGenerator('custom', $customGenerator);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->tokenGenerator('custom');

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

        app(KeychainManager::class)->registerTokenHasher('custom', $customHasher);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->tokenHasher('custom');

        expect($retrieved)->toBe($customHasher);
        expect($retrieved->hash('test'))->toStartWith('custom_');
    });

    it('registers custom audit driver', function (): void {
        $customDriver = new class() implements AuditDriver
        {
            public array $logs = [];

            public function log(PersonalAccessToken $token, AuditEvent $event, array $metadata = []): void
            {
                $this->logs[] = [
                    'token_id' => $token->id,
                    'event' => $event,
                    'metadata' => $metadata,
                ];
            }

            public function getLogsForToken(PersonalAccessToken $token): Collection
            {
                return new Collection(array_filter($this->logs, fn (array $log): bool => $log['token_id'] === $token->id));
            }
        };

        app(KeychainManager::class)->registerAuditDriver('custom', $customDriver);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->auditDriver('custom');

        expect($retrieved)->toBe($customDriver);
        expect($retrieved->logs)->toBeArray();
    });

    it('registers custom revocation strategy', function (): void {
        $customStrategy = new class() implements RevocationStrategy
        {
            public int $revokeCount = 0;

            public function revoke(PersonalAccessToken $token): void
            {
                ++$this->revokeCount;
                $token->revoke();
            }

            public function getAffectedTokens(PersonalAccessToken $token): Collection
            {
                return new Collection([$token]);
            }
        };

        app(KeychainManager::class)->registerRevocationStrategy('custom', $customStrategy);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->revocationStrategy('custom');

        expect($retrieved)->toBe($customStrategy);
        expect($retrieved->revokeCount)->toBe(0);

        // Use it
        $user = createUser();
        $token = createToken($user);
        Keychain::revoke($token, 'custom');

        expect($retrieved->revokeCount)->toBe(1);
    });

    it('registers custom rotation strategy', function (): void {
        $customStrategy = new class() implements RotationStrategy
        {
            public int $rotateCount = 0;

            public function rotate(PersonalAccessToken $oldToken, PersonalAccessToken $newToken): void
            {
                ++$this->rotateCount;
                $oldToken->revoke();
            }

            public function isOldTokenValid(PersonalAccessToken $oldToken): bool
            {
                return !$oldToken->isRevoked();
            }

            public function gracePeriodMinutes(): ?int
            {
                return null;
            }
        };

        app(KeychainManager::class)->registerRotationStrategy('custom', $customStrategy);

        // Verify we can retrieve it
        $retrieved = app(KeychainManager::class)->rotationStrategy('custom');

        expect($retrieved)->toBe($customStrategy);
        expect($retrieved->rotateCount)->toBe(0);

        // Use it
        $user = createUser();
        $token = createToken($user);
        Keychain::rotate($token, 'custom');

        expect($retrieved->rotateCount)->toBe(1);
    });

    it('allows multiple registrations of same type', function (): void {
        $generator1 = new RandomTokenGenerator();
        $generator2 = new RandomTokenGenerator();

        app(KeychainManager::class)->registerTokenGenerator('gen1', $generator1);
        app(KeychainManager::class)->registerTokenGenerator('gen2', $generator2);

        expect(app(KeychainManager::class)->tokenGenerator('gen1'))->toBe($generator1);
        expect(app(KeychainManager::class)->tokenGenerator('gen2'))->toBe($generator2);
    });

    it('can override default implementations via registration', function (): void {
        $originalHasher = app(KeychainManager::class)->tokenHasher('sha256');

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
        app(KeychainManager::class)->registerTokenHasher('sha256', $customHasher);

        $retrieved = app(KeychainManager::class)->tokenHasher('sha256');

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

        app(KeychainManager::class)->registerTokenType('persistent', $customType);

        // Retrieve multiple times
        $first = app(KeychainManager::class)->tokenType('persistent');
        $second = app(KeychainManager::class)->tokenType('persistent');
        $third = app(KeychainManager::class)->tokenType('persistent');

        expect($first)->toBe($customType);
        expect($second)->toBe($customType);
        expect($third)->toBe($customType);
    });
});

describe('KeychainManager - Integration with Registered Components', function (): void {
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

        app(KeychainManager::class)->registerTokenGenerator('test_custom', $customGenerator);

        // Temporarily change default generator
        config(['keychain.generator.default' => 'test_custom']);

        $user = createUser();
        $result = Keychain::for($user)->issue('sk', 'Test with Custom Generator');

        // Restore default
        config(['keychain.generator.default' => 'seam']);

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

            public function revoke(PersonalAccessToken $token): void
            {
                $this->log[] = 'revoked_token_'.$token->id;
                $token->revoke();
            }

            public function getAffectedTokens(PersonalAccessToken $token): Collection
            {
                return new Collection([$token]);
            }
        };

        app(KeychainManager::class)->registerRevocationStrategy('logging', $loggingStrategy);

        $user = createUser();
        $token = createToken($user);

        Keychain::revoke($token, 'logging');

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

            public function rotate(PersonalAccessToken $oldToken, PersonalAccessToken $newToken): void
            {
                $this->log[] = 'rotated_'.$oldToken->id.'_to_'.$newToken->id;
                $oldToken->revoke();
            }

            public function isOldTokenValid(PersonalAccessToken $oldToken): bool
            {
                return !$oldToken->isRevoked();
            }

            public function gracePeriodMinutes(): ?int
            {
                return null;
            }
        };

        app(KeychainManager::class)->registerRotationStrategy('logging', $loggingStrategy);

        $user = createUser();
        $token = createToken($user);
        $oldId = $token->id;

        $newToken = Keychain::rotate($token, 'logging');

        expect($callLog)->toHaveCount(1);
        expect($callLog[0])->toContain('rotated_'.$oldId.'_to_'.$newToken->accessToken->id);
    });
});
