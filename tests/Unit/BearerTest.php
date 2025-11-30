<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\BearerConfig;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\Facades\Bearer;

describe('Bearer', function (): void {
    describe('Happy Path', function (): void {
        test('useAccessTokenModel sets custom model class', function (): void {
            // Arrange
            $customModel = 'App\\Models\\CustomAccessToken';
            $originalModel = BearerConfig::$personalAccessTokenModel;

            // Act
            Bearer::useAccessTokenModel($customModel);

            // Assert
            expect(BearerConfig::$personalAccessTokenModel)->toBe($customModel);
            expect(Bearer::personalAccessTokenModel())->toBe($customModel);
        })->defer(function () use (&$originalModel): void {
            BearerConfig::$personalAccessTokenModel = $originalModel ?? AccessToken::class;
        });

        test('useAccessTokenGroupModel sets custom model class', function (): void {
            // Arrange
            $customModel = 'App\\Models\\CustomAccessTokenGroup';
            $originalModel = BearerConfig::$tokenGroupModel;

            // Act
            Bearer::useAccessTokenGroupModel($customModel);

            // Assert
            expect(BearerConfig::$tokenGroupModel)->toBe($customModel);
            expect(Bearer::tokenGroupModel())->toBe($customModel);
        })->defer(function () use (&$originalModel): void {
            BearerConfig::$tokenGroupModel = $originalModel ?? AccessTokenGroup::class;
        });

        test('getAccessTokenFromRequestUsing sets callback', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenRetrievalCallback;
            $callback = fn ($request) => $request->bearerToken();

            // Act
            Bearer::getAccessTokenFromRequestUsing($callback);

            // Assert
            expect(BearerConfig::$accessTokenRetrievalCallback)->toBe($callback);
            expect(BearerConfig::$accessTokenRetrievalCallback)->toBeInstanceOf(Closure::class);
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing sets callback', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenAuthenticationCallback;
            $callback = fn ($token): bool => $token !== null;

            // Act
            Bearer::authenticateAccessTokensUsing($callback);

            // Assert
            expect(BearerConfig::$accessTokenAuthenticationCallback)->toBe($callback);
            expect(BearerConfig::$accessTokenAuthenticationCallback)->toBeInstanceOf(Closure::class);
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('getAccessTokenFromRequestUsing callback can be invoked', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenRetrievalCallback;
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
            Bearer::getAccessTokenFromRequestUsing($callback);

            // Act
            $result = (BearerConfig::$accessTokenRetrievalCallback)($mockRequest);

            // Assert
            expect($result)->toBe($expectedToken);
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing callback can be invoked', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenAuthenticationCallback;
            $mockToken = new AccessToken([
                'type' => 'secret_key',
                'environment' => 'testing',
                'name' => 'Test Token',
                'token' => hash('sha256', 'plain-text-token'),
                'prefix' => 'sk_test',
                'abilities' => ['*'],
            ]);

            $callback = fn ($token): bool => $token !== null && $token->type === 'secret_key';
            Bearer::authenticateAccessTokensUsing($callback);

            // Act
            $result = (BearerConfig::$accessTokenAuthenticationCallback)($mockToken);

            // Assert
            expect($result)->toBeTrue();
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });
    });

    describe('Edge Cases', function (): void {
        test('useAccessTokenModel accepts fully qualified class names', function (): void {
            // Arrange
            $originalModel = BearerConfig::$personalAccessTokenModel;
            $fqcn = AccessToken::class;

            // Act
            Bearer::useAccessTokenModel($fqcn);

            // Assert
            expect(BearerConfig::$personalAccessTokenModel)->toBe($fqcn);
        })->defer(function () use (&$originalModel): void {
            BearerConfig::$personalAccessTokenModel = $originalModel ?? AccessToken::class;
        });

        test('useAccessTokenGroupModel accepts fully qualified class names', function (): void {
            // Arrange
            $originalModel = BearerConfig::$tokenGroupModel;
            $fqcn = AccessTokenGroup::class;

            // Act
            Bearer::useAccessTokenGroupModel($fqcn);

            // Assert
            expect(BearerConfig::$tokenGroupModel)->toBe($fqcn);
        })->defer(function () use (&$originalModel): void {
            BearerConfig::$tokenGroupModel = $originalModel ?? AccessTokenGroup::class;
        });

        test('getAccessTokenFromRequestUsing can be set to null', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenRetrievalCallback;
            Bearer::getAccessTokenFromRequestUsing(fn (): string => 'test');

            // Act
            Bearer::getAccessTokenFromRequestUsing(null);

            // Assert
            expect(BearerConfig::$accessTokenRetrievalCallback)->toBeNull();
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('authenticateAccessTokensUsing can be set to null', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenAuthenticationCallback;
            Bearer::authenticateAccessTokensUsing(fn (): true => true);

            // Act
            Bearer::authenticateAccessTokensUsing(null);

            // Assert
            expect(BearerConfig::$accessTokenAuthenticationCallback)->toBeNull();
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('callback setters can be called multiple times', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenRetrievalCallback;
            $firstCallback = fn (): string => 'first';
            $secondCallback = fn (): string => 'second';

            // Act
            Bearer::getAccessTokenFromRequestUsing($firstCallback);
            $firstResult = BearerConfig::$accessTokenRetrievalCallback;

            Bearer::getAccessTokenFromRequestUsing($secondCallback);
            $secondResult = BearerConfig::$accessTokenRetrievalCallback;

            // Assert
            expect($firstResult)->toBe($firstCallback);
            expect($secondResult)->toBe($secondCallback);
            expect($firstResult)->not->toBe($secondResult);
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenRetrievalCallback = $originalCallback;
        });

        test('model setters can be called multiple times', function (): void {
            // Arrange
            $originalModel = BearerConfig::$personalAccessTokenModel;
            $firstModel = 'App\\Models\\CustomAccessToken';
            $secondModel = 'App\\Models\\AnotherCustomAccessToken';

            // Act
            Bearer::useAccessTokenModel($firstModel);
            $firstResult = BearerConfig::$personalAccessTokenModel;

            Bearer::useAccessTokenModel($secondModel);
            $secondResult = BearerConfig::$personalAccessTokenModel;

            // Assert
            expect($firstResult)->toBe($firstModel);
            expect($secondResult)->toBe($secondModel);
            expect($firstResult)->not->toBe($secondResult);
        })->defer(function () use (&$originalModel): void {
            BearerConfig::$personalAccessTokenModel = $originalModel ?? AccessToken::class;
        });

        test('callbacks with complex logic can be stored', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenAuthenticationCallback;
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
            Bearer::authenticateAccessTokensUsing($callback);

            $validToken = new AccessToken(['type' => 'secret_key']);
            $invalidToken = new AccessToken(['type' => 'invalid']);

            // Assert
            expect(BearerConfig::$accessTokenAuthenticationCallback)->toBe($callback);
            expect((BearerConfig::$accessTokenAuthenticationCallback)($validToken))->toBeTrue();
            expect((BearerConfig::$accessTokenAuthenticationCallback)($invalidToken))->toBeFalse();
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenAuthenticationCallback = $originalCallback;
        });

        test('default model values can be restored', function (): void {
            // Arrange
            $defaultAccessTokenModel = AccessToken::class;
            $defaultAccessTokenGroupModel = AccessTokenGroup::class;

            // Act
            Bearer::useAccessTokenModel('App\\Models\\CustomAccessToken');
            Bearer::useAccessTokenGroupModel('App\\Models\\CustomAccessTokenGroup');

            expect(BearerConfig::$personalAccessTokenModel)->toBe('App\\Models\\CustomAccessToken');
            expect(BearerConfig::$tokenGroupModel)->toBe('App\\Models\\CustomAccessTokenGroup');

            Bearer::useAccessTokenModel($defaultAccessTokenModel);
            Bearer::useAccessTokenGroupModel($defaultAccessTokenGroupModel);

            // Assert
            expect(BearerConfig::$personalAccessTokenModel)->toBe($defaultAccessTokenModel);
            expect(BearerConfig::$tokenGroupModel)->toBe($defaultAccessTokenGroupModel);
        });

        test('callbacks preserve closure scope', function (): void {
            // Arrange
            $originalCallback = BearerConfig::$accessTokenRetrievalCallback;
            $capturedValue = 'captured';

            $callback = fn ($request): string => $capturedValue.':'.$request;

            // Act
            Bearer::getAccessTokenFromRequestUsing($callback);

            // Assert
            $result = (BearerConfig::$accessTokenRetrievalCallback)('test');
            expect($result)->toBe('captured:test');
        })->defer(function () use (&$originalCallback): void {
            BearerConfig::$accessTokenRetrievalCallback = $originalCallback;
        });
    });
});
