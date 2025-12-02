<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Support\TokenComponents;
use Cline\Bearer\TokenGenerators\RandomTokenGenerator;
use Cline\Bearer\TokenGenerators\SeamTokenGenerator;
use Cline\Bearer\TokenGenerators\UuidTokenGenerator;
use Illuminate\Support\Str;

describe('SeamTokenGenerator', function (): void {
    describe('Happy Path', function (): void {
        test('generates tokens in correct format', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();

            // Act
            $token = $generator->generate('sk', 'test');

            // Assert
            expect($token)->toStartWith('sk_test_');
            expect(mb_strlen($token))->toBeGreaterThan(15);
        });

        test('generates tokens with different prefixes and environments', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();

            // Act
            $secretTest = $generator->generate('sk', 'test');
            $secretLive = $generator->generate('sk', 'live');
            $publishableTest = $generator->generate('pk', 'test');
            $publishableLive = $generator->generate('pk', 'live');

            // Assert
            expect($secretTest)->toStartWith('sk_test_');
            expect($secretLive)->toStartWith('sk_live_');
            expect($publishableTest)->toStartWith('pk_test_');
            expect($publishableLive)->toStartWith('pk_live_');
        });

        test('generates unique tokens', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();

            // Act
            $token1 = $generator->generate('sk', 'test');
            $token2 = $generator->generate('sk', 'test');

            // Assert
            expect($token1)->not->toBe($token2);
        });

        test('generates tokens with base58 characters only', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();
            $base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

            // Act
            $token = $generator->generate('sk', 'test');
            $parts = explode('_', $token);
            $secret = $parts[2];

            // Assert
            for ($i = 0; $i < mb_strlen($secret); ++$i) {
                expect(str_contains($base58Alphabet, $secret[$i]))->toBeTrue();
            }
        });

        test('parses valid tokens correctly', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();
            $token = $generator->generate('pk', 'live');

            // Act
            $components = $generator->parse($token);

            // Assert
            expect($components)->toBeInstanceOf(TokenComponents::class);
            expect($components->prefix)->toBe('pk');
            expect($components->environment)->toBe('live');
            expect($components->secret)->not->toBeEmpty();
            expect($components->fullToken)->toBe($token);
        });

        test('hashes tokens consistently', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();
            $token = $generator->generate('sk', 'test');

            // Act
            $hash1 = $generator->hash($token);
            $hash2 = $generator->hash($token);

            // Assert
            expect($hash1)->toBe($hash2);
            expect(mb_strlen($hash1))->toBe(64); // SHA256 produces 64 hex characters
        });

        test('verifies correct tokens', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();
            $token = $generator->generate('sk', 'test');
            $hash = $generator->hash($token);

            // Act & Assert
            expect($generator->verify($token, $hash))->toBeTrue();
        });

        test('rejects incorrect tokens', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();
            $token = $generator->generate('sk', 'test');
            $hash = $generator->hash($token);

            // Act & Assert
            expect($generator->verify('wrong_token', $hash))->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('returns null for tokens with incorrect part count', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();

            // Act
            $invalidToken1 = $generator->parse('sk_test');
            $invalidToken2 = $generator->parse('sk_test_abc_extra');

            // Assert
            expect($invalidToken1)->toBeNull();
            expect($invalidToken2)->toBeNull();
        });

        test('returns null for tokens with empty parts', function (): void {
            // Arrange
            $generator = new SeamTokenGenerator();

            // Act
            $emptyPrefix = $generator->parse('_test_abc123');
            $emptyEnvironment = $generator->parse('sk__abc123');
            $emptySecret = $generator->parse('sk_test_');

            // Assert
            expect($emptyPrefix)->toBeNull();
            expect($emptyEnvironment)->toBeNull();
            expect($emptySecret)->toBeNull();
        });
    });
});

describe('UuidTokenGenerator', function (): void {
    describe('Happy Path', function (): void {
        test('generates tokens in correct format', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $token = $generator->generate('sk', 'test');

            // Assert
            expect($token)->toStartWith('sk_test_');
            $parts = explode('_', $token);
            expect($parts[2])->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/');
        });

        test('generates valid UUID v4 tokens', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $token = $generator->generate('pk', 'live');
            $parts = explode('_', $token);

            // Assert
            expect(Str::isUuid($parts[2]))->toBeTrue();
        });

        test('generates unique tokens', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $token1 = $generator->generate('sk', 'test');
            $token2 = $generator->generate('sk', 'test');

            // Assert
            expect($token1)->not->toBe($token2);
        });

        test('parses valid UUID tokens correctly', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();
            $token = $generator->generate('rk', 'test');

            // Act
            $components = $generator->parse($token);

            // Assert
            expect($components)->toBeInstanceOf(TokenComponents::class);
            expect($components->prefix)->toBe('rk');
            expect($components->environment)->toBe('test');
            expect(Str::isUuid($components->secret))->toBeTrue();
        });

        test('hashes and verifies tokens', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();
            $token = $generator->generate('sk', 'test');
            $hash = $generator->hash($token);

            // Act & Assert
            expect($generator->verify($token, $hash))->toBeTrue();
            expect($generator->verify('wrong_token', $hash))->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('returns null for tokens with invalid UUID', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $invalidUuid = $generator->parse('sk_test_not-a-valid-uuid');

            // Assert
            expect($invalidUuid)->toBeNull();
        });

        test('returns null for tokens with incorrect part count', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $invalid = $generator->parse('sk_test');

            // Assert
            expect($invalid)->toBeNull();
        });

        test('returns null for tokens with empty parts', function (): void {
            // Arrange
            $generator = new UuidTokenGenerator();

            // Act
            $emptyPrefix = $generator->parse('_test_550e8400-e29b-41d4-a716-446655440000');

            // Assert
            expect($emptyPrefix)->toBeNull();
        });
    });
});

describe('RandomTokenGenerator', function (): void {
    describe('Happy Path', function (): void {
        test('generates tokens in correct format', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $token = $generator->generate('sk', 'test');

            // Assert
            expect($token)->toStartWith('sk_test_');
            $parts = explode('_', $token);
            expect(mb_strlen($parts[2]))->toBe(48); // 40 chars entropy + 8 chars checksum
        });

        test('generates tokens with different prefixes and environments', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $secretTest = $generator->generate('sk', 'test');
            $secretLive = $generator->generate('sk', 'live');

            // Assert
            expect($secretTest)->toStartWith('sk_test_');
            expect($secretLive)->toStartWith('sk_live_');
        });

        test('generates unique tokens', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $token1 = $generator->generate('sk', 'test');
            $token2 = $generator->generate('sk', 'test');

            // Assert
            expect($token1)->not->toBe($token2);
        });

        test('parses valid tokens correctly', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();
            $token = $generator->generate('pk', 'live');

            // Act
            $components = $generator->parse($token);

            // Assert
            expect($components)->toBeInstanceOf(TokenComponents::class);
            expect($components->prefix)->toBe('pk');
            expect($components->environment)->toBe('live');
            expect(mb_strlen($components->secret))->toBe(48);
        });

        test('hashes and verifies tokens', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();
            $token = $generator->generate('sk', 'test');
            $hash = $generator->hash($token);

            // Act & Assert
            expect($generator->verify($token, $hash))->toBeTrue();
            expect($generator->verify('wrong_token', $hash))->toBeFalse();
        });

        test('secret contains CRC32 checksum', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $token = $generator->generate('sk', 'test');
            $parts = explode('_', $token);
            $secret = $parts[2];

            // Assert - Secret should be 48 chars (40 entropy + 8 checksum)
            expect(mb_strlen($secret))->toBe(48);
            $entropy = mb_substr($secret, 0, 40);
            $checksum = mb_substr($secret, 40);
            expect(mb_strlen($checksum))->toBe(8);
        });
    });

    describe('Edge Cases', function (): void {
        test('returns null for tokens with incorrect secret length', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $tooShort = $generator->parse('sk_test_tooshort');
            $tooLong = $generator->parse('sk_test_'.str_repeat('a', 100));

            // Assert
            expect($tooShort)->toBeNull();
            expect($tooLong)->toBeNull();
        });

        test('returns null for tokens with incorrect part count', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $invalid = $generator->parse('sk_test');

            // Assert
            expect($invalid)->toBeNull();
        });

        test('returns null for tokens with empty parts', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();

            // Act
            $emptyPrefix = $generator->parse('_test_'.str_repeat('a', 48));

            // Assert
            expect($emptyPrefix)->toBeNull();
        });

        test('parses exactly 48 character secrets', function (): void {
            // Arrange
            $generator = new RandomTokenGenerator();
            $validSecret = str_repeat('a', 48);

            // Act
            $components = $generator->parse('sk_test_'.$validSecret);

            // Assert
            expect($components)->toBeInstanceOf(TokenComponents::class);
        });
    });
});
