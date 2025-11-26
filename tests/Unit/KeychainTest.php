<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Database\Models\TokenGroup;
use Cline\Keychain\Facades\Keychain;
use Cline\Keychain\KeychainConfig;

describe('Keychain', function (): void {
    describe('Happy Path', function (): void {
        test('usePersonalAccessTokenModel sets custom model class', function (): void {
            // Arrange
            $customModel = 'App\\Models\\CustomPersonalAccessToken';
            $originalModel = KeychainConfig::$personalAccessTokenModel;

            // Act
            Keychain::usePersonalAccessTokenModel($customModel);

            // Assert
            expect(KeychainConfig::$personalAccessTokenModel)->toBe($customModel);
            expect(Keychain::personalAccessTokenModel())->toBe($customModel);
        })->defer(function () use (&$originalModel): void {
            KeychainConfig::$personalAccessTokenModel = $originalModel ?? PersonalAccessToken::class;
        });

        test('useTokenGroupModel sets custom model class', function (): void {
            // Arrange
            $customModel = 'App\\Models\\CustomTokenGroup';
            $originalModel = KeychainConfig::$tokenGroupModel;

            // Act
            Keychain::useTokenGroupModel($customModel);

            // Assert
            expect(KeychainConfig::$tokenGroupModel)->toBe($customModel);
            expect(Keychain::tokenGroupModel())->toBe($customModel);
        })->defer(function () use (&$originalModel): void {
            KeychainConfig::$tokenGroupModel = $originalModel ?? TokenGroup::class;
        });

        test('getAccessTokenFromRequestUsing sets callback', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenRetrievalCallback;
            $callback = fn ($request) => $request->bearerToken();

            // Act
            Keychain::getAccessTokenFromRequestUsing($callback);

            // Assert
            expect(KeychainConfig::$accessTokenRetrievalCallback)->toBe($callback);
            expect(KeychainConfig::$accessTokenRetrievalCallback)->toBeInstanceOf(Closure::class);
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing sets callback', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenAuthenticationCallback;
            $callback = fn ($token): bool => $token !== null;

            // Act
            Keychain::authenticateAccessTokensUsing($callback);

            // Assert
            expect(KeychainConfig::$accessTokenAuthenticationCallback)->toBe($callback);
            expect(KeychainConfig::$accessTokenAuthenticationCallback)->toBeInstanceOf(Closure::class);
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('getAccessTokenFromRequestUsing callback can be invoked', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenRetrievalCallback;
            $expectedToken = 'sk_test_abc123';
            $mockRequest = new readonly class($expectedToken)
            {
                public function __construct(
                    private string $token,
                ) {}

                public function bearerToken(): string
                {
                    return $this->token;
                }
            };

            $callback = fn ($request) => $request->bearerToken();
            Keychain::getAccessTokenFromRequestUsing($callback);

            // Act
            $result = (KeychainConfig::$accessTokenRetrievalCallback)($mockRequest);

            // Assert
            expect($result)->toBe($expectedToken);
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing callback can be invoked', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenAuthenticationCallback;
            $mockToken = new PersonalAccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Test Token',
                'token' => hash('sha256', 'plain-text-token'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);

            $callback = fn ($token): bool => $token !== null && $token->type === 'secret_key';
            Keychain::authenticateAccessTokensUsing($callback);

            // Act
            $result = (KeychainConfig::$accessTokenAuthenticationCallback)($mockToken);

            // Assert
            expect($result)->toBeTrue();
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });
    });

    describe('Edge Cases', function (): void {
        test('usePersonalAccessTokenModel accepts fully qualified class names', function (): void {
            // Arrange
            $originalModel = KeychainConfig::$personalAccessTokenModel;
            $fqcn = PersonalAccessToken::class;

            // Act
            Keychain::usePersonalAccessTokenModel($fqcn);

            // Assert
            expect(KeychainConfig::$personalAccessTokenModel)->toBe($fqcn);
        })->defer(function () use (&$originalModel): void {
            KeychainConfig::$personalAccessTokenModel = $originalModel ?? PersonalAccessToken::class;
        });

        test('useTokenGroupModel accepts fully qualified class names', function (): void {
            // Arrange
            $originalModel = KeychainConfig::$tokenGroupModel;
            $fqcn = TokenGroup::class;

            // Act
            Keychain::useTokenGroupModel($fqcn);

            // Assert
            expect(KeychainConfig::$tokenGroupModel)->toBe($fqcn);
        })->defer(function () use (&$originalModel): void {
            KeychainConfig::$tokenGroupModel = $originalModel ?? TokenGroup::class;
        });

        test('getAccessTokenFromRequestUsing can be set to null', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenRetrievalCallback;
            Keychain::getAccessTokenFromRequestUsing(fn (): string => 'test');

            // Act
            Keychain::getAccessTokenFromRequestUsing(null);

            // Assert
            expect(KeychainConfig::$accessTokenRetrievalCallback)->toBeNull();
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing can be set to null', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenAuthenticationCallback;
            Keychain::authenticateAccessTokensUsing(fn (): true => true);

            // Act
            Keychain::authenticateAccessTokensUsing(null);

            // Assert
            expect(KeychainConfig::$accessTokenAuthenticationCallback)->toBeNull();
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('callback setters can be called multiple times', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenRetrievalCallback;
            $firstCallback = fn (): string => 'first';
            $secondCallback = fn (): string => 'second';

            // Act
            Keychain::getAccessTokenFromRequestUsing($firstCallback);
            $firstResult = KeychainConfig::$accessTokenRetrievalCallback;

            Keychain::getAccessTokenFromRequestUsing($secondCallback);
            $secondResult = KeychainConfig::$accessTokenRetrievalCallback;

            // Assert
            expect($firstResult)->toBe($firstCallback);
            expect($secondResult)->toBe($secondCallback);
            expect($firstResult)->not->toBe($secondResult);
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('model setters can be called multiple times', function (): void {
            // Arrange
            $originalModel = KeychainConfig::$personalAccessTokenModel;
            $firstModel = 'App\\Models\\CustomPersonalAccessToken';
            $secondModel = 'App\\Models\\AnotherCustomPersonalAccessToken';

            // Act
            Keychain::usePersonalAccessTokenModel($firstModel);
            $firstResult = KeychainConfig::$personalAccessTokenModel;

            Keychain::usePersonalAccessTokenModel($secondModel);
            $secondResult = KeychainConfig::$personalAccessTokenModel;

            // Assert
            expect($firstResult)->toBe($firstModel);
            expect($secondResult)->toBe($secondModel);
            expect($firstResult)->not->toBe($secondResult);
        })->defer(function () use (&$originalModel): void {
            KeychainConfig::$personalAccessTokenModel = $originalModel ?? PersonalAccessToken::class;
        });

        test('callbacks with complex logic can be stored', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenAuthenticationCallback;
            $callback = function ($token): bool {
                if ($token === null) {
                    return false;
                }

                if (!isset($token->type)) {
                    return false;
                }

                return in_array($token->type, ['secret_key', 'publishable_key'], true);
            };

            // Act
            Keychain::authenticateAccessTokensUsing($callback);

            $validToken = new PersonalAccessToken(['type' => 'secret_key']);
            $invalidToken = new PersonalAccessToken(['type' => 'invalid']);

            // Assert
            expect(KeychainConfig::$accessTokenAuthenticationCallback)->toBe($callback);
            expect((KeychainConfig::$accessTokenAuthenticationCallback)($validToken))->toBeTrue();
            expect((KeychainConfig::$accessTokenAuthenticationCallback)($invalidToken))->toBeFalse();
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('default model values can be restored', function (): void {
            // Arrange
            $defaultPersonalAccessTokenModel = PersonalAccessToken::class;
            $defaultTokenGroupModel = TokenGroup::class;

            // Act
            Keychain::usePersonalAccessTokenModel('App\\Models\\CustomPersonalAccessToken');
            Keychain::useTokenGroupModel('App\\Models\\CustomTokenGroup');

            expect(KeychainConfig::$personalAccessTokenModel)->toBe('App\\Models\\CustomPersonalAccessToken');
            expect(KeychainConfig::$tokenGroupModel)->toBe('App\\Models\\CustomTokenGroup');

            Keychain::usePersonalAccessTokenModel($defaultPersonalAccessTokenModel);
            Keychain::useTokenGroupModel($defaultTokenGroupModel);

            // Assert
            expect(KeychainConfig::$personalAccessTokenModel)->toBe($defaultPersonalAccessTokenModel);
            expect(KeychainConfig::$tokenGroupModel)->toBe($defaultTokenGroupModel);
        });

        test('callbacks preserve closure scope', function (): void {
            // Arrange
            $originalCallback = KeychainConfig::$accessTokenRetrievalCallback;
            $capturedValue = 'captured';

            $callback = fn ($request): string => $capturedValue.':'.$request;

            // Act
            Keychain::getAccessTokenFromRequestUsing($callback);

            // Assert
            $result = (KeychainConfig::$accessTokenRetrievalCallback)('test');
            expect($result)->toBe('captured:test');
        })->defer(function () use (&$originalCallback): void {
            KeychainConfig::$accessTokenRetrievalCallback = $originalCallback;
        });
    });
});
