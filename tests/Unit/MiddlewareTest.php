<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Contracts\HasAbilities;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Exceptions\AuthenticationException;
use Cline\Bearer\Exceptions\InvalidEnvironmentException;
use Cline\Bearer\Exceptions\InvalidTokenTypeException;
use Cline\Bearer\Exceptions\MissingAbilityException;
use Cline\Bearer\Http\Middleware\CheckAbilities;
use Cline\Bearer\Http\Middleware\CheckEnvironment;
use Cline\Bearer\Http\Middleware\CheckForAnyAbility;
use Cline\Bearer\Http\Middleware\CheckTokenType;
use Cline\Bearer\Http\Middleware\EnsureFrontendRequestsAreStateful;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Tests\Fixtures\User;

function createMiddlewareTestToken(User $user, string $type = 'sk', array $attributes = []): AccessToken
{
    static $counter = 0;
    ++$counter;

    $token = AccessToken::query()->forceCreate([
        'tokenable_type' => User::class,
        'tokenable_id' => $user->id,
        'type' => $type,
        'environment' => $attributes['environment'] ?? 'test',
        'name' => $attributes['name'] ?? 'Test Token '.$counter,
        'prefix' => $type.'_test',
        'token' => 'test-token-hash-'.uniqid(),
        'abilities' => $attributes['abilities'] ?? ['*'],
    ]);

    // Attach token to user
    $user->withAccessToken($token);

    return $token;
}

describe('CheckAbilities', function (): void {
    describe('Happy Path', function (): void {
        test('passes when user has all required abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts', 'write:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'write:posts',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when user has single required ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['admin:access']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'admin:access',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when user has more abilities than required', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts', 'write:posts', 'delete:posts', 'admin:access']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'write:posts',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });
    });

    describe('Sad Path', function (): void {
        test('throws AuthenticationException when no user is present', function (): void {
            // Arrange
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $middleware = new CheckAbilities();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws AuthenticationException when user has no current access token', function (): void {
            // Arrange
            $user = createUser();
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws MissingAbilityException when token lacks first required ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['write:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
                'write:posts',
            ))->toThrow(MissingAbilityException::class);
        });

        test('throws MissingAbilityException when token lacks second required ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
                'write:posts',
            ))->toThrow(MissingAbilityException::class);
        });

        test('throws MissingAbilityException when token has no abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => []]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(MissingAbilityException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('handles ability names with special characters', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['posts:read', 'users:write:admin']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'posts:read',
                'users:write:admin',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('handles case-sensitive ability names', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['Read:Posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckAbilities();

            // Act & Assert - Should fail because 'read:posts' !== 'Read:Posts'
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(MissingAbilityException::class);
        });
    });
});

describe('CheckEnvironment', function (): void {
    describe('Happy Path', function (): void {
        test('passes when token environment matches single allowed environment', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'test',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when token environment matches one of multiple allowed environments', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'live']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'test',
                'live',
                'development',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when token environment is first in allowed list', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'development']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'development',
                'staging',
                'production',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });
    });

    describe('Sad Path', function (): void {
        test('throws AuthenticationException when no user is present', function (): void {
            // Arrange
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $middleware = new CheckEnvironment();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws AuthenticationException when user has no current access token', function (): void {
            // Arrange
            $user = createUser();
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws InvalidEnvironmentException when environment does not match', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'production']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
            ))->toThrow(InvalidEnvironmentException::class);
        });

        test('throws InvalidEnvironmentException when environment not in allowed list', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'staging']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
                'live',
                'development',
            ))->toThrow(InvalidEnvironmentException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('throws AuthenticationException when environment is not a string', function (): void {
            // Arrange
            $user = createUser();

            // Create a custom token-like object with non-string environment
            $mockToken = new class() implements HasAbilities
            {
                public mixed $environment = 123; // Non-string environment

                public function can(string $ability): bool
                {
                    return true;
                }

                public function cant(string $ability): bool
                {
                    return false;
                }
            };

            $user->withAccessToken($mockToken);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
            ))->toThrow(AuthenticationException::class);
        });

        test('handles environment names with special characters', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'pre-production']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'pre-production',
                'production',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('handles case-sensitive environment matching', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => [], 'environment' => 'Test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckEnvironment();

            // Act & Assert - Should fail because 'Test' !== 'test'
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'test',
            ))->toThrow(InvalidEnvironmentException::class);
        });
    });
});

describe('CheckForAnyAbility', function (): void {
    describe('Happy Path', function (): void {
        test('passes when token has first ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'admin:access',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when token has second ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['admin:access']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'admin:access',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('passes when token has all abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts', 'write:posts', 'admin:access']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'write:posts',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('passes when token has only one of many abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['delete:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'write:posts',
                'delete:posts',
                'admin:access',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });
    });

    describe('Sad Path', function (): void {
        test('throws AuthenticationException when no user is present', function (): void {
            // Arrange
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $middleware = new CheckForAnyAbility();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws AuthenticationException when user has no current access token', function (): void {
            // Arrange
            $user = createUser();
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws MissingAbilityException when token has none of the required abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['update:users']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
                'write:posts',
            ))->toThrow(MissingAbilityException::class);
        });

        test('throws MissingAbilityException when token has no abilities', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => []]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'read:posts',
            ))->toThrow(MissingAbilityException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('returns early on first matching ability', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['read:posts']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act - First ability matches, should return immediately
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'read:posts',
                'write:posts',
                'delete:posts',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('handles ability names with special characters', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['abilities' => ['posts:read:public']]);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckForAnyAbility();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'posts:read:public',
                'admin:access',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });
    });
});

describe('CheckTokenType', function (): void {
    describe('Happy Path', function (): void {
        test('passes when token type matches single allowed type', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'sk', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'sk',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
            expect($response)->toBe('success');
        });

        test('passes when token type matches one of multiple allowed types', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'pk', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'sk',
                'pk',
                'rk',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('passes when token type is first in allowed list', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'rk', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'rk',
                'sk',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });
    });

    describe('Sad Path', function (): void {
        test('throws AuthenticationException when no user is present', function (): void {
            // Arrange
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $middleware = new CheckTokenType();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'sk',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws AuthenticationException when user has no current access token', function (): void {
            // Arrange
            $user = createUser();
            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'sk',
            ))->toThrow(AuthenticationException::class);
        });

        test('throws InvalidTokenTypeException when type does not match', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'pk', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'sk',
            ))->toThrow(InvalidTokenTypeException::class);
        });

        test('throws InvalidTokenTypeException when type not in allowed list', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'rk', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();

            // Act & Assert
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'sk',
                'pk',
            ))->toThrow(InvalidTokenTypeException::class);
        });
    });

    describe('Edge Cases', function (): void {
        test('handles custom token types', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'custom', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();
            $nextCalled = false;

            // Act
            $response = $middleware->handle(
                $request,
                function ($req) use (&$nextCalled): string {
                    $nextCalled = true;

                    return 'success';
                },
                'custom',
            );

            // Assert
            expect($nextCalled)->toBeTrue();
        });

        test('handles case-sensitive type matching', function (): void {
            // Arrange
            $user = createUser();
            $token = createMiddlewareTestToken($user, 'SK', ['environment' => 'test']);

            $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
            $request->setUserResolver(fn (): User => $user);

            $middleware = new CheckTokenType();

            // Act & Assert - Should fail because 'SK' !== 'sk'
            expect(fn (): mixed => $middleware->handle(
                $request,
                fn ($req): string => 'success',
                'sk',
            ))->toThrow(InvalidTokenTypeException::class);
        });
    });
});

describe('EnsureFrontendRequestsAreStateful', function (): void {
    describe('fromFrontend() static method', function (): void {
        describe('Happy Path', function (): void {
            test('returns true when referer matches configured stateful domain', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['localhost', 'app.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'http://localhost/page');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('returns true when origin matches configured stateful domain', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['app.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('origin', 'https://app.example.com');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('returns true when domain with port matches', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['localhost:3000']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'http://localhost:3000/app');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('returns true when wildcard matches current host', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['*']);
                $request = Request::create('http://api.example.com/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'http://api.example.com/page');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });
        });

        describe('Sad Path', function (): void {
            test('returns false when no referer or origin header present', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['localhost']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeFalse();
            });

            test('returns false when domain does not match configured stateful domains', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['app.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'https://evil.com/page');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeFalse();
            });

            test('returns false when stateful config is empty', function (): void {
                // Arrange
                Config::set('bearer.stateful', []);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'http://localhost/page');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeFalse();
            });
        });

        describe('Edge Cases', function (): void {
            test('strips https protocol from domain', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['secure.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'https://secure.example.com/admin');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('strips http protocol from domain', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['localhost']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('origin', 'http://localhost');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('prefers referer over origin when both present', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['referer.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'https://referer.example.com/page');
                $request->headers->set('origin', 'https://origin.example.com');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('uses origin when referer is not present', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['origin.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('origin', 'https://origin.example.com');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });

            test('handles multiple stateful domains', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['app.example.com', 'admin.example.com', 'localhost:3000']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'https://admin.example.com/dashboard');

                // Act
                $result = EnsureFrontendRequestsAreStateful::fromFrontend($request);

                // Assert
                expect($result)->toBeTrue();
            });
        });
    });

    describe('handle() method', function (): void {
        describe('Happy Path', function (): void {
            test('configures secure cookies when not from frontend', function (): void {
                // Arrange
                Config::set('bearer.stateful', []);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $middleware = new EnsureFrontendRequestsAreStateful();

                // Act
                $middleware->handle($request, fn ($req): string => 'success');

                // Assert
                expect(config('session.http_only'))->toBeTrue();
                expect(config('session.same_site'))->toBe('lax');
            });

            test('passes request through when not from frontend', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['app.example.com']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                // No referer/origin header - not from frontend

                $middleware = new EnsureFrontendRequestsAreStateful();
                $nextCalled = false;

                // Act
                $response = $middleware->handle(
                    $request,
                    function ($req) use (&$nextCalled): string {
                        $nextCalled = true;
                        // Bearer attribute should NOT be set for non-frontend
                        expect($req->attributes->get('bearer'))->toBeNull();

                        return 'success';
                    },
                );

                // Assert
                expect($nextCalled)->toBeTrue();
                expect($response)->toBe('success');
            });

            test('passes request through when referer does not match stateful domains', function (): void {
                // Arrange
                Config::set('bearer.stateful', ['localhost']);
                $request = Request::create('/test', Symfony\Component\HttpFoundation\Request::METHOD_GET);
                $request->headers->set('referer', 'https://external.com/page');

                $middleware = new EnsureFrontendRequestsAreStateful();
                $nextCalled = false;

                // Act
                $response = $middleware->handle(
                    $request,
                    function ($req) use (&$nextCalled): string {
                        $nextCalled = true;

                        return 'success';
                    },
                );

                // Assert
                expect($nextCalled)->toBeTrue();
                expect($response)->toBe('success');
            });
        });
    });
});
