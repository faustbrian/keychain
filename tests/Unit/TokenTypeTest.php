<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Contracts\TokenType;
use Cline\Bearer\Exceptions\InvalidTokenTypeException;
use Cline\Bearer\TokenTypes\ConfigurableTokenType;
use Cline\Bearer\TokenTypes\TokenTypeRegistry;

describe('ConfigurableTokenType (Secret)', function (): void {
    describe('Happy Path', function (): void {
        test('has correct name', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->name())->toBe('Secret');
        });

        test('has correct prefix', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->prefix())->toBe('sk');
        });

        test('has wildcard default abilities', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultAbilities())->toBe(['*']);
        });

        test('has no default expiration', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultExpiration())->toBeNull();
        });

        test('has no rate limit', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultRateLimit())->toBeNull();
        });

        test('allows both test and live environments', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->allowedEnvironments())->toBe(['test', 'live']);
        });

        test('is server side only', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
                'abilities' => ['*'],
                'expiration' => null,
                'rate_limit' => null,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->isServerSideOnly())->toBeTrue();
        });
    });
});

describe('ConfigurableTokenType (Publishable)', function (): void {
    describe('Happy Path', function (): void {
        test('has correct name', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->name())->toBe('Publishable');
        });

        test('has correct prefix', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->prefix())->toBe('pk');
        });

        test('has read-only default abilities', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->defaultAbilities())->toBe(['read']);
        });

        test('has 30 day default expiration', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->defaultExpiration())->toBe(43_200); // 60 * 24 * 30
        });

        test('has rate limit of 1000 requests per minute', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->defaultRateLimit())->toBe(1_000);
        });

        test('allows both test and live environments', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->allowedEnvironments())->toBe(['test', 'live']);
        });

        test('is not server side only', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
                'abilities' => ['read'],
                'expiration' => 43_200,
                'rate_limit' => 1_000,
                'environments' => ['test', 'live'],
                'server_side_only' => false,
            ]);

            // Act & Assert
            expect($type->isServerSideOnly())->toBeFalse();
        });
    });
});

describe('ConfigurableTokenType (Restricted)', function (): void {
    describe('Happy Path', function (): void {
        test('has correct name', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->name())->toBe('Restricted');
        });

        test('has correct prefix', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->prefix())->toBe('rk');
        });

        test('has empty default abilities', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultAbilities())->toBe([]);
        });

        test('has 1 year default expiration', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultExpiration())->toBe(525_600); // 60 * 24 * 365
        });

        test('has rate limit of 100 requests per minute', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->defaultRateLimit())->toBe(100);
        });

        test('allows both test and live environments', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->allowedEnvironments())->toBe(['test', 'live']);
        });

        test('is server side only', function (): void {
            // Arrange
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
                'abilities' => [],
                'expiration' => 525_600,
                'rate_limit' => 100,
                'environments' => ['test', 'live'],
                'server_side_only' => true,
            ]);

            // Act & Assert
            expect($type->isServerSideOnly())->toBeTrue();
        });
    });
});

describe('TokenTypeRegistry', function (): void {
    describe('Happy Path', function (): void {
        test('registers token types', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);

            // Act
            $registry->register('secret', $type);

            // Assert
            expect($registry->has('secret'))->toBeTrue();
        });

        test('retrieves registered token types', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $type = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $registry->register('secret', $type);

            // Act
            $retrieved = $registry->get('secret');

            // Assert
            expect($retrieved)->toBe($type);
            expect($retrieved)->toBeInstanceOf(ConfigurableTokenType::class);
        });

        test('registers multiple token types', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $secretType = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $publishableType = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
            ]);
            $restrictedType = ConfigurableTokenType::fromConfig([
                'name' => 'Restricted',
                'prefix' => 'rk',
            ]);

            // Act
            $registry->register('secret', $secretType);
            $registry->register('publishable', $publishableType);
            $registry->register('restricted', $restrictedType);

            // Assert
            expect($registry->has('secret'))->toBeTrue();
            expect($registry->has('publishable'))->toBeTrue();
            expect($registry->has('restricted'))->toBeTrue();
        });

        test('returns all registered types', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $secretType = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $publishableType = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
            ]);
            $registry->register('secret', $secretType);
            $registry->register('publishable', $publishableType);

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toHaveCount(2);
            expect($all['secret'])->toBe($secretType);
            expect($all['publishable'])->toBe($publishableType);
        });

        test('finds token type by prefix', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $secretType = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $publishableType = ConfigurableTokenType::fromConfig([
                'name' => 'Publishable',
                'prefix' => 'pk',
            ]);
            $registry->register('secret', $secretType);
            $registry->register('publishable', $publishableType);

            // Act
            $foundSecret = $registry->findByPrefix('sk');
            $foundPublishable = $registry->findByPrefix('pk');

            // Assert
            expect($foundSecret)->toBe($secretType);
            expect($foundPublishable)->toBe($publishableType);
        });

        test('replaces existing token type when re-registered', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $type1 = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $type2 = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $registry->register('secret', $type1);

            // Act
            $registry->register('secret', $type2);

            // Assert
            expect($registry->get('secret'))->toBe($type2);
            expect($registry->get('secret'))->not->toBe($type1);
        });
    });

    describe('Edge Cases', function (): void {
        test('returns false when checking unregistered type', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();

            // Act & Assert
            expect($registry->has('nonexistent'))->toBeFalse();
        });

        test('returns null when finding by nonexistent prefix', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $registry->register('secret', ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]));

            // Act
            $found = $registry->findByPrefix('xx');

            // Assert
            expect($found)->toBeNull();
        });

        test('returns empty array when no types registered', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();

            // Act
            $all = $registry->all();

            // Assert
            expect($all)->toBe([]);
        });

        test('finds first matching type when multiple types share prefix', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $type1 = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $type2 = ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]);
            $registry->register('secret1', $type1);
            $registry->register('secret2', $type2);

            // Act
            $found = $registry->findByPrefix('sk');

            // Assert - Should return first match
            expect($found)->toBeIn([$type1, $type2]);
        });
    });

    describe('Sad Path', function (): void {
        test('throws exception when getting unregistered type', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();

            // Act & Assert
            expect(fn (): TokenType => $registry->get('nonexistent'))
                ->toThrow(InvalidTokenTypeException::class, "Token type 'nonexistent' is not registered in the configuration.");
        });

        test('throws exception with correct message for unregistered type', function (): void {
            // Arrange
            $registry = new TokenTypeRegistry();
            $registry->register('secret', ConfigurableTokenType::fromConfig([
                'name' => 'Secret',
                'prefix' => 'sk',
            ]));

            // Act & Assert
            expect(fn (): TokenType => $registry->get('custom'))
                ->toThrow(InvalidTokenTypeException::class, "Token type 'custom' is not registered in the configuration.");
        });
    });
});
