<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\NewAccessToken;
use Illuminate\Contracts\Support\Arrayable;

describe('NewAccessToken', function (): void {
    describe('Happy Path', function (): void {
        test('creates instance with accessToken and plainTextToken properties', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Test Token',
                'token' => hash('sha256', 'plain-text-token'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);
            $plainText = 'sk_test_abc123def456ghi789';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken)->toBeInstanceOf(NewAccessToken::class);
            expect($newAccessToken->accessToken)->toBe($personalAccessToken);
            expect($newAccessToken->plainTextToken)->toBe($plainText);
        });

        test('accessToken property holds the AccessToken model', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'production',
                'name' => 'API Token',
                'token' => hash('sha256', 'secure-token'),
                'prefix' => 'sk_live',
                'abilities' => ['read', 'write'],
            ]);
            $plainText = 'sk_live_xyz987uvw654rst321';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken->accessToken)->toBeInstanceOf(AccessToken::class);
            expect($newAccessToken->accessToken->type)->toBe('secret_key');
            expect($newAccessToken->accessToken->name)->toBe('API Token');
            expect($newAccessToken->accessToken->prefix)->toBe('sk_live');
        });

        test('plainTextToken property holds the plain text string', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'publishable_key',
                'environment' => 'development',
                'name' => 'Dev Token',
                'token' => hash('sha256', 'dev-token'),
                'prefix' => 'pk_dev',
                'abilities' => ['read'],
            ]);
            $plainText = 'pk_dev_123abc456def789ghi';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken->plainTextToken)->toBeString();
            expect($newAccessToken->plainTextToken)->toBe('pk_dev_123abc456def789ghi');
        });

        test('toArray returns array with accessToken and plainTextToken keys', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Array Test Token',
                'token' => hash('sha256', 'array-token'),
                'prefix' => 'sk_test',
                'abilities' => ['admin'],
            ]);
            $plainText = 'sk_test_array123token456';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);
            $array = $newAccessToken->toArray();

            // Assert
            expect($array)->toBeArray();
            expect($array)->toHaveKeys(['accessToken', 'plainTextToken']);
            expect($array['accessToken'])->toBe($personalAccessToken);
            expect($array['plainTextToken'])->toBe($plainText);
        });

        test('jsonSerialize returns same as toArray', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'JSON Test Token',
                'token' => hash('sha256', 'json-token'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);
            $plainText = 'sk_test_json123serialize456';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);
            $jsonSerializeResult = $newAccessToken->jsonSerialize();
            $toArrayResult = $newAccessToken->toArray();

            // Assert
            expect($jsonSerializeResult)->toBe($toArrayResult);
            expect($jsonSerializeResult)->toEqual([
                'accessToken' => $personalAccessToken,
                'plainTextToken' => $plainText,
            ]);
        });

        test('implements Arrayable interface', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Interface Test',
                'token' => hash('sha256', 'interface-token'),
                'prefix' => 'sk_test',
                'abilities' => ['read'],
            ]);
            $plainText = 'sk_test_interface123';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken)->toBeInstanceOf(Arrayable::class);
        });

        test('implements JsonSerializable interface', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'JSON Interface Test',
                'token' => hash('sha256', 'json-interface-token'),
                'prefix' => 'sk_test',
                'abilities' => ['write'],
            ]);
            $plainText = 'sk_test_jsoninterface456';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken)->toBeInstanceOf(JsonSerializable::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('handles empty abilities array', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'No Abilities Token',
                'token' => hash('sha256', 'no-abilities'),
                'prefix' => 'sk_test',
                'abilities' => [],
            ]);
            $plainText = 'sk_test_noabilities789';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken->accessToken->abilities)->toBeArray();
            expect($newAccessToken->accessToken->abilities)->toBeEmpty();
        });

        test('handles token with metadata', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Metadata Token',
                'token' => hash('sha256', 'metadata-token'),
                'prefix' => 'sk_test',
                'abilities' => ['read'],
                'metadata' => ['source' => 'api', 'version' => '2.0'],
            ]);
            $plainText = 'sk_test_metadata123';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken->accessToken->metadata)->toBe(['source' => 'api', 'version' => '2.0']);
        });

        test('handles different token types', function (): void {
            // Arrange
            $secretKey = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Secret Key',
                'token' => hash('sha256', 'secret'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);
            $publishableKey = new AccessToken([
                'type' => 'publishable_key',
                'environment' => 'testing',
                'name' => 'Publishable Key',
                'token' => hash('sha256', 'publishable'),
                'prefix' => 'pk_test',
                'abilities' => ['read'],
            ]);

            // Act
            $secretToken = new NewAccessToken($secretKey, 'sk_test_secret123');
            $publishableToken = new NewAccessToken($publishableKey, 'pk_test_public456');

            // Assert
            expect($secretToken->accessToken->type)->toBe('secret_key');
            expect($publishableToken->accessToken->type)->toBe('publishable_key');
        });

        test('handles different environments', function (): void {
            // Arrange
            $prodToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'production',
                'name' => 'Production Token',
                'token' => hash('sha256', 'prod'),
                'prefix' => 'sk_live',
                'abilities' => ['*'],
            ]);
            $devToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'development',
                'name' => 'Development Token',
                'token' => hash('sha256', 'dev'),
                'prefix' => 'sk_dev',
                'abilities' => ['*'],
            ]);

            // Act
            $prodAccessToken = new NewAccessToken($prodToken, 'sk_live_prod123');
            $devAccessToken = new NewAccessToken($devToken, 'sk_dev_dev456');

            // Assert
            expect($prodAccessToken->accessToken->environment)->toBe('production');
            expect($devAccessToken->accessToken->environment)->toBe('development');
        });

        test('toArray preserves object references', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Reference Test',
                'token' => hash('sha256', 'reference'),
                'prefix' => 'sk_test',
                'abilities' => ['admin'],
            ]);
            $plainText = 'sk_test_reference789';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);
            $array = $newAccessToken->toArray();

            // Assert
            expect($array['accessToken'])->toBe($personalAccessToken);
            expect($array['accessToken'])->not->toBeArray();
        });

        test('handles long plain text tokens', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Long Token',
                'token' => hash('sha256', 'long-token'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);
            $longPlainText = 'sk_test_'.str_repeat('a', 256);

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $longPlainText);

            // Assert
            expect($newAccessToken->plainTextToken)->toHaveLength(264); // sk_test_ (8) + 256
            expect($newAccessToken->plainTextToken)->toBe($longPlainText);
        });

        test('handles tokens with special characters in name', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Token @#$% with (special) chars!',
                'token' => hash('sha256', 'special'),
                'prefix' => 'sk_test',
                'abilities' => ['read'],
            ]);
            $plainText = 'sk_test_special123';

            // Act
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Assert
            expect($newAccessToken->accessToken->name)->toBe('Token @#$% with (special) chars!');
        });

        test('readonly properties cannot be modified', function (): void {
            // Arrange
            $personalAccessToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Readonly Test',
                'token' => hash('sha256', 'readonly'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);
            $plainText = 'sk_test_readonly123';
            $newAccessToken = new NewAccessToken($personalAccessToken, $plainText);

            // Act & Assert
            try {
                $newAccessToken->plainTextToken = 'modified';
                expect(false)->toBeTrue('Should have thrown error');
            } catch (Error $error) {
                expect($error->getMessage())->toContain('Cannot modify readonly property');
            }
        });
    });
});
