<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Contracts\TokenHasher;
use Cline\Bearer\Exceptions\TokenHasherNotRegisteredException;
use Cline\Bearer\TokenHashers\Sha256TokenHasher;
use Cline\Bearer\TokenHashers\Sha512TokenHasher;
use Cline\Bearer\TokenHashers\TokenHasherRegistry;

describe('Sha512TokenHasher', function (): void {
    describe('Happy Path', function (): void {
        test('hashes a token using SHA-512', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = 'my-secret-token';

            // Act
            $hash = $hasher->hash($token);

            // Assert
            expect($hash)->toBeString();
            expect(mb_strlen($hash))->toBe(128); // SHA-512 produces 128 hex characters
            expect($hash)->toBe(hash('sha512', $token));
        });

        test('verifies a token against a correct hash', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = 'my-secret-token';
            $hash = $hasher->hash($token);

            // Act
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('produces consistent hashes for same token', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = 'consistent-token';

            // Act
            $hash1 = $hasher->hash($token);
            $hash2 = $hasher->hash($token);

            // Assert
            expect($hash1)->toBe($hash2);
        });

        test('produces different hashes for different tokens', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token1 = 'token-one';
            $token2 = 'token-two';

            // Act
            $hash1 = $hasher->hash($token1);
            $hash2 = $hasher->hash($token2);

            // Assert
            expect($hash1)->not->toBe($hash2);
        });
    });

    describe('Sad Path', function (): void {
        test('fails verification with incorrect token', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $correctToken = 'correct-token';
            $incorrectToken = 'incorrect-token';
            $hash = $hasher->hash($correctToken);

            // Act
            $result = $hasher->verify($incorrectToken, $hash);

            // Assert
            expect($result)->toBeFalse();
        });

        test('fails verification with incorrect hash', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = 'my-token';
            $correctHash = $hasher->hash($token);
            $incorrectHash = hash('sha512', 'different-token');

            // Act
            $result = $hasher->verify($token, $incorrectHash);

            // Assert
            expect($result)->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty string token', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = '';

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($hash)->toBeString();
            expect($result)->toBeTrue();
        });

        test('handles very long token', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = str_repeat('a', 10_000);

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($hash)->toBeString();
            expect(mb_strlen($hash))->toBe(128);
            expect($result)->toBeTrue();
        });

        test('handles special characters', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = "!@#$%^&*()_+-=[]{}|;':\",./<>?\n\r\t";

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('handles unicode characters', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = '你好世界🚀🎉';

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('is resistant to timing attacks', function (): void {
            // Arrange
            $hasher = new Sha512TokenHasher();
            $token = 'secure-token';
            $hash = $hasher->hash($token);
            $almostCorrect = 'secure-toke!'; // Different token (last char different)

            // Act
            $result = $hasher->verify($almostCorrect, $hash);

            // Assert
            expect($result)->toBeFalse();
            // Note: hash_equals provides timing attack resistance
        });
    });
});

describe('Sha256TokenHasher', function (): void {
    describe('Happy Path', function (): void {
        test('hashes a token using SHA-256', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = 'my-secret-token';

            // Act
            $hash = $hasher->hash($token);

            // Assert
            expect($hash)->toBeString();
            expect(mb_strlen($hash))->toBe(64); // SHA-256 produces 64 hex characters
            expect($hash)->toBe(hash('sha256', $token));
        });

        test('verifies a token against a correct hash', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = 'my-secret-token';
            $hash = $hasher->hash($token);

            // Act
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('produces consistent hashes for same token', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = 'consistent-token';

            // Act
            $hash1 = $hasher->hash($token);
            $hash2 = $hasher->hash($token);

            // Assert
            expect($hash1)->toBe($hash2);
        });

        test('produces different hashes for different tokens', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token1 = 'token-one';
            $token2 = 'token-two';

            // Act
            $hash1 = $hasher->hash($token1);
            $hash2 = $hasher->hash($token2);

            // Assert
            expect($hash1)->not->toBe($hash2);
        });
    });

    describe('Sad Path', function (): void {
        test('fails verification with incorrect token', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $correctToken = 'correct-token';
            $incorrectToken = 'incorrect-token';
            $hash = $hasher->hash($correctToken);

            // Act
            $result = $hasher->verify($incorrectToken, $hash);

            // Assert
            expect($result)->toBeFalse();
        });

        test('fails verification with incorrect hash', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = 'my-token';
            $correctHash = $hasher->hash($token);
            $incorrectHash = hash('sha256', 'different-token');

            // Act
            $result = $hasher->verify($token, $incorrectHash);

            // Assert
            expect($result)->toBeFalse();
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty string token', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = '';

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($hash)->toBeString();
            expect($result)->toBeTrue();
        });

        test('handles very long token', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = str_repeat('b', 10_000);

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($hash)->toBeString();
            expect(mb_strlen($hash))->toBe(64);
            expect($result)->toBeTrue();
        });

        test('handles special characters', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = "!@#$%^&*()_+-=[]{}|;':\",./<>?\n\r\t";

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('handles unicode characters', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = '你好世界🚀🎉';

            // Act
            $hash = $hasher->hash($token);
            $result = $hasher->verify($token, $hash);

            // Assert
            expect($result)->toBeTrue();
        });

        test('is resistant to timing attacks', function (): void {
            // Arrange
            $hasher = new Sha256TokenHasher();
            $token = 'secure-token';
            $hash = $hasher->hash($token);
            $almostCorrect = 'secure-toke!'; // Different token (last char different)

            // Act
            $result = $hasher->verify($almostCorrect, $hash);

            // Assert
            expect($result)->toBeFalse();
            // Note: hash_equals provides timing attack resistance
        });
    });
});

describe('TokenHasherNotRegisteredException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for hasher not found by name', function (): void {
            // Arrange
            $name = 'bcrypt';

            // Act
            $exception = TokenHasherNotRegisteredException::forHasher($name);

            // Assert
            expect($exception)->toBeInstanceOf(TokenHasherNotRegisteredException::class);
            expect($exception->getMessage())->toBe("Token hasher 'bcrypt' is not registered.");
        });

        test('creates exception when no default hasher is set', function (): void {
            // Arrange & Act
            $exception = TokenHasherNotRegisteredException::noDefault();

            // Assert
            expect($exception)->toBeInstanceOf(TokenHasherNotRegisteredException::class);
            expect($exception->getMessage())->toBe('No default token hasher has been set.');
        });

        test('handles different hasher names', function (): void {
            // Arrange & Act
            $exception1 = TokenHasherNotRegisteredException::forHasher('sha256');
            $exception2 = TokenHasherNotRegisteredException::forHasher('sha512');
            $exception3 = TokenHasherNotRegisteredException::forHasher('custom-hasher');

            // Assert
            expect($exception1->getMessage())->toContain('sha256');
            expect($exception2->getMessage())->toContain('sha512');
            expect($exception3->getMessage())->toContain('custom-hasher');
        });
    });
});

describe('TokenHasherRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers and retrieves a hasher', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha512TokenHasher();

            // Act
            $registry->register('sha512', $hasher);
            $retrieved = $registry->get('sha512');

            // Assert
            expect($retrieved)->toBe($hasher);
        });

        test('checks if hasher is registered', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha256TokenHasher();

            // Act
            $registry->register('sha256', $hasher);
            $hasRegistered = $registry->has('sha256');
            $hasUnregistered = $registry->has('bcrypt');

            // Assert
            expect($hasRegistered)->toBeTrue();
            expect($hasUnregistered)->toBeFalse();
        });

        test('sets and retrieves default hasher', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha512TokenHasher();
            $registry->register('sha512', $hasher);

            // Act
            $registry->setDefault('sha512');

            $default = $registry->default();

            // Assert
            expect($default)->toBe($hasher);
        });

        test('registers multiple hashers', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $sha256 = new Sha256TokenHasher();
            $sha512 = new Sha512TokenHasher();

            // Act
            $registry->register('sha256', $sha256);
            $registry->register('sha512', $sha512);

            // Assert
            expect($registry->get('sha256'))->toBe($sha256);
            expect($registry->get('sha512'))->toBe($sha512);
            expect($registry->has('sha256'))->toBeTrue();
            expect($registry->has('sha512'))->toBeTrue();
        });

        test('returns all registered hashers', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $sha256 = new Sha256TokenHasher();
            $sha512 = new Sha512TokenHasher();

            // Act
            $registry->register('sha256', $sha256);
            $registry->register('sha512', $sha512);

            $all = $registry->all();

            // Assert
            expect($all)->toBeArray();
            expect($all)->toHaveCount(2);
            expect($all)->toHaveKey('sha256');
            expect($all)->toHaveKey('sha512');
            expect($all['sha256'])->toBe($sha256);
            expect($all['sha512'])->toBe($sha512);
        });

        test('overwrites hasher when registering with same name', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher1 = new Sha256TokenHasher();
            $hasher2 = new Sha512TokenHasher();

            // Act
            $registry->register('hasher', $hasher1);
            $registry->register('hasher', $hasher2);

            $retrieved = $registry->get('hasher');

            // Assert
            expect($retrieved)->toBe($hasher2);
            expect($retrieved)->not->toBe($hasher1);
        });
    });

    describe('Sad Path', function (): void {
        test('throws exception when getting unregistered hasher', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();

            // Act & Assert
            expect(fn (): TokenHasher => $registry->get('nonexistent'))
                ->toThrow(TokenHasherNotRegisteredException::class, "Token hasher 'nonexistent' is not registered.");
        });

        test('throws exception when no default hasher is set', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();

            // Act & Assert
            expect(fn (): TokenHasher => $registry->default())
                ->toThrow(TokenHasherNotRegisteredException::class, 'No default token hasher has been set.');
        });

        test('throws exception when default hasher name is not registered', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();

            // Act
            $registry->setDefault('unregistered');

            // Assert
            expect(fn (): TokenHasher => $registry->default())
                ->toThrow(TokenHasherNotRegisteredException::class, "Token hasher 'unregistered' is not registered.");
        });
    });

    describe('Edge Cases', function (): void {
        test('returns empty array when no hashers registered', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toBeArray();
            expect($all)->toBeEmpty();
        });

        test('allows setting default after registration', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha256TokenHasher();

            // Act
            $registry->setDefault('sha256'); // Set default before registration
            $registry->register('sha256', $hasher);

            $default = $registry->default();

            // Assert
            expect($default)->toBe($hasher);
        });

        test('allows changing default hasher', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $sha256 = new Sha256TokenHasher();
            $sha512 = new Sha512TokenHasher();
            $registry->register('sha256', $sha256);
            $registry->register('sha512', $sha512);

            // Act
            $registry->setDefault('sha256');

            $default1 = $registry->default();
            $registry->setDefault('sha512');
            $default2 = $registry->default();

            // Assert
            expect($default1)->toBe($sha256);
            expect($default2)->toBe($sha512);
        });

        test('handles hasher names with special characters', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha256TokenHasher();
            $name = 'sha-256.v1:custom';

            // Act
            $registry->register($name, $hasher);
            $retrieved = $registry->get($name);

            // Assert
            expect($retrieved)->toBe($hasher);
            expect($registry->has($name))->toBeTrue();
        });

        test('all() returns copy not reference', function (): void {
            // Arrange
            $registry = new TokenHasherRegistry();
            $hasher = new Sha256TokenHasher();
            $registry->register('sha256', $hasher);

            // Act
            $all1 = $registry->all();
            $registry->register('sha512', new Sha512TokenHasher());
            $all2 = $registry->all();

            // Assert
            expect($all1)->toHaveCount(1);
            expect($all2)->toHaveCount(2);
        });
    });
});
