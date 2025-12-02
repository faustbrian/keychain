<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Exceptions\InvalidConfigurationException;
use Cline\Bearer\TokenTypes\ConfigurableTokenType;

describe('ConfigurableTokenType', function (): void {
    describe('Happy Path', function (): void {
        test('creates instance from valid config with all fields', function (): void {
            // Arrange
            $config = [
                'name' => 'Integration',
                'prefix' => 'int',
                'abilities' => ['api:read', 'api:write'],
                'expiration' => 43_200,
                'rate_limit' => 500,
                'environments' => ['production', 'staging'],
                'server_side_only' => true,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType)->toBeInstanceOf(ConfigurableTokenType::class);
            expect($tokenType->name())->toBe('Integration');
            expect($tokenType->prefix())->toBe('int');
            expect($tokenType->defaultAbilities())->toBe(['api:read', 'api:write']);
            expect($tokenType->defaultExpiration())->toBe(43_200);
            expect($tokenType->defaultRateLimit())->toBe(500);
            expect($tokenType->allowedEnvironments())->toBe(['production', 'staging']);
            expect($tokenType->isServerSideOnly())->toBeTrue();
        });

        test('creates instance from config with only required fields', function (): void {
            // Arrange
            $config = [
                'name' => 'Temporary',
                'prefix' => 'tmp',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType)->toBeInstanceOf(ConfigurableTokenType::class);
            expect($tokenType->name())->toBe('Temporary');
            expect($tokenType->prefix())->toBe('tmp');
        });

        test('applies default abilities when not provided', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultAbilities())->toBe(['*']);
        });

        test('applies null expiration when not provided', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultExpiration())->toBeNull();
        });

        test('applies null rate limit when not provided', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultRateLimit())->toBeNull();
        });

        test('applies default environments when not provided', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->allowedEnvironments())->toBe(['test', 'live']);
        });

        test('applies false for server_side_only when not provided', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->isServerSideOnly())->toBeFalse();
        });

        test('accepts zero expiration', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => 0,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultExpiration())->toBe(0);
        });

        test('accepts zero rate limit', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => 0,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultRateLimit())->toBe(0);
        });

        test('accepts empty abilities array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => [],
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultAbilities())->toBe([]);
        });

        test('accepts empty environments array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => [],
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->allowedEnvironments())->toBe([]);
        });
    });

    describe('Sad Path - Missing Name', function (): void {
        test('throws exception when name field is missing', function (): void {
            // Arrange
            $config = [
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });

        test('throws exception when name is empty string', function (): void {
            // Arrange
            $config = [
                'name' => '',
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });

        test('throws exception when name is not a string', function (): void {
            // Arrange
            $config = [
                'name' => 123,
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });

        test('throws exception when name is null', function (): void {
            // Arrange
            $config = [
                'name' => null,
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });

        test('throws exception when name is array', function (): void {
            // Arrange
            $config = [
                'name' => ['Test'],
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });

        test('throws exception when name is boolean', function (): void {
            // Arrange
            $config = [
                'name' => true,
                'prefix' => 'tst',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "name" field.');
        });
    });

    describe('Sad Path - Missing Prefix', function (): void {
        test('throws exception when prefix field is missing', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });

        test('throws exception when prefix is empty string', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => '',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });

        test('throws exception when prefix is not a string', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 456,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });

        test('throws exception when prefix is null', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => null,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });

        test('throws exception when prefix is array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => ['tst'],
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });

        test('throws exception when prefix is boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => false,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type configuration must include a non-empty "prefix" field.');
        });
    });

    describe('Sad Path - Invalid Abilities Type', function (): void {
        test('throws exception when abilities is not an array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => 'api:read',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "abilities" must be an array.');
        });

        test('throws exception when abilities is integer', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => 123,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "abilities" must be an array.');
        });

        test('throws exception when abilities is boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => true,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "abilities" must be an array.');
        });

        test('accepts null abilities and applies default', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => null,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultAbilities())->toBe(['*']);
        });
    });

    describe('Sad Path - Invalid Expiration Type', function (): void {
        test('throws exception when expiration is not an integer', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => '3600',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "expiration" must be a positive integer or null.');
        });

        test('throws exception when expiration is negative', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => -100,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "expiration" must be a positive integer or null.');
        });

        test('throws exception when expiration is float', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => 3_600.5,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "expiration" must be a positive integer or null.');
        });

        test('throws exception when expiration is boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => false,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "expiration" must be a positive integer or null.');
        });

        test('throws exception when expiration is array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => [3_600],
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "expiration" must be a positive integer or null.');
        });
    });

    describe('Sad Path - Invalid Rate Limit Type', function (): void {
        test('throws exception when rate_limit is not an integer', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => '500',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "rate_limit" must be a positive integer or null.');
        });

        test('throws exception when rate_limit is negative', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => -50,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "rate_limit" must be a positive integer or null.');
        });

        test('throws exception when rate_limit is float', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => 100.5,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "rate_limit" must be a positive integer or null.');
        });

        test('throws exception when rate_limit is boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => true,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "rate_limit" must be a positive integer or null.');
        });

        test('throws exception when rate_limit is array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => [100],
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "rate_limit" must be a positive integer or null.');
        });
    });

    describe('Sad Path - Invalid Environments Type', function (): void {
        test('throws exception when environments is not an array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => 'production',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "environments" must be an array.');
        });

        test('throws exception when environments is integer', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => 123,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "environments" must be an array.');
        });

        test('throws exception when environments is boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => false,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "environments" must be an array.');
        });

        test('accepts null environments and applies default', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => null,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->allowedEnvironments())->toBe(['test', 'live']);
        });
    });

    describe('Sad Path - Invalid Server Side Only Type', function (): void {
        test('throws exception when server_side_only is not a boolean', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'server_side_only' => 'true',
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "server_side_only" must be a boolean.');
        });

        test('throws exception when server_side_only is integer', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'server_side_only' => 1,
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "server_side_only" must be a boolean.');
        });

        test('accepts null server_side_only and applies default', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'server_side_only' => null,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->isServerSideOnly())->toBeFalse();
        });

        test('throws exception when server_side_only is array', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'server_side_only' => [true],
            ];

            // Act & Assert
            expect(fn (): ConfigurableTokenType => ConfigurableTokenType::fromConfig($config))
                ->toThrow(InvalidConfigurationException::class, 'Token type "server_side_only" must be a boolean.');
        });
    });

    describe('Edge Cases', function (): void {
        test('handles single character name', function (): void {
            // Arrange
            $config = [
                'name' => 'T',
                'prefix' => 't',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->name())->toBe('T');
        });

        test('handles single character prefix', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 't',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->prefix())->toBe('t');
        });

        test('handles long name', function (): void {
            // Arrange
            $longName = str_repeat('VeryLongTokenTypeName', 10);
            $config = [
                'name' => $longName,
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->name())->toBe($longName);
        });

        test('handles name with special characters', function (): void {
            // Arrange
            $config = [
                'name' => 'Test-Token_Type.v1',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->name())->toBe('Test-Token_Type.v1');
        });

        test('handles prefix with special characters', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst_v1',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->prefix())->toBe('tst_v1');
        });

        test('handles large expiration value', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'expiration' => 525_600, // One year in minutes
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultExpiration())->toBe(525_600);
        });

        test('handles large rate limit value', function (): void {
            // Arrange
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'rate_limit' => 1_000_000,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultRateLimit())->toBe(1_000_000);
        });

        test('handles many abilities', function (): void {
            // Arrange
            $abilities = [];

            for ($i = 0; $i < 100; ++$i) {
                $abilities[] = 'ability:'.$i;
            }

            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'abilities' => $abilities,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->defaultAbilities())->toBe($abilities);
            expect($tokenType->defaultAbilities())->toHaveCount(100);
        });

        test('handles many environments', function (): void {
            // Arrange
            $environments = ['test', 'development', 'staging', 'production', 'qa', 'uat', 'demo'];
            $config = [
                'name' => 'Test',
                'prefix' => 'tst',
                'environments' => $environments,
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->allowedEnvironments())->toBe($environments);
        });

        test('handles unicode in name', function (): void {
            // Arrange
            $config = [
                'name' => 'Test 测试 🔐',
                'prefix' => 'tst',
            ];

            // Act
            $tokenType = ConfigurableTokenType::fromConfig($config);

            // Assert
            expect($tokenType->name())->toBe('Test 测试 🔐');
        });
    });
});
