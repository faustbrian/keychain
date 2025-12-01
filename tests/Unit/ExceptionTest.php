<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Carbon\CarbonImmutable;
use Cline\Bearer\Exceptions\DomainRestrictionException;
use Cline\Bearer\Exceptions\InvalidConfigurationException;
use Cline\Bearer\Exceptions\InvalidEnvironmentException;
use Cline\Bearer\Exceptions\InvalidPrimaryKeyValueException;
use Cline\Bearer\Exceptions\InvalidTokenTypeException;
use Cline\Bearer\Exceptions\IpRestrictionException;
use Cline\Bearer\Exceptions\MissingAbilityException;
use Cline\Bearer\Exceptions\RateLimitExceededException;
use Cline\Bearer\Exceptions\TokenExpiredException;
use Cline\Bearer\Exceptions\TokenGeneratorNotRegisteredException;
use Cline\Bearer\Exceptions\TokenNotFoundException;
use Cline\Bearer\Exceptions\TokenRevokedException;
use Illuminate\Support\Facades\Date;

describe('DomainRestrictionException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception with notAllowed factory method', function (): void {
            // Arrange
            $domain = 'evil.com';
            $allowedDomains = ['example.com', 'api.example.com'];

            // Act
            $exception = DomainRestrictionException::notAllowed($domain, $allowedDomains);

            // Assert
            expect($exception)->toBeInstanceOf(DomainRestrictionException::class);
            expect($exception->getMessage())->toBe("Domain 'evil.com' is not allowed. Allowed domains: example.com, api.example.com");
        });

        test('handles single allowed domain', function (): void {
            // Arrange
            $domain = 'test.com';
            $allowedDomains = ['example.com'];

            // Act
            $exception = DomainRestrictionException::notAllowed($domain, $allowedDomains);

            // Assert
            expect($exception->getMessage())->toContain('Allowed domains: example.com');
        });

        test('handles multiple allowed domains', function (): void {
            // Arrange
            $domain = 'unauthorized.com';
            $allowedDomains = ['app.example.com', 'api.example.com', 'cdn.example.com'];

            // Act
            $exception = DomainRestrictionException::notAllowed($domain, $allowedDomains);

            // Assert
            expect($exception->getMessage())->toContain('app.example.com, api.example.com, cdn.example.com');
        });

        test('creates exception with forDomain factory method', function (): void {
            // Arrange
            $domain = 'unauthorized.com';

            // Act
            $exception = DomainRestrictionException::forDomain($domain);

            // Assert
            expect($exception)->toBeInstanceOf(DomainRestrictionException::class);
            expect($exception->getMessage())->toBe('Domain unauthorized.com is not allowed for this token.');
        });

        test('creates exception for missing origin/referer header', function (): void {
            // Arrange & Act
            $exception = DomainRestrictionException::missingHeader();

            // Assert
            expect($exception)->toBeInstanceOf(DomainRestrictionException::class);
            expect($exception->getMessage())->toBe('No origin or referer header present for domain validation.');
        });
    });
});

describe('InvalidConfigurationException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for missing token type', function (): void {
            // Arrange
            $type = 'custom';

            // Act
            $exception = InvalidConfigurationException::missingTokenType($type);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidConfigurationException::class);
            expect($exception->getMessage())->toBe("Token type 'custom' is not configured. Add it to the 'token_types' configuration.");
        });

        test('creates exception for missing audit driver', function (): void {
            // Arrange
            $driver = 'elasticsearch';

            // Act
            $exception = InvalidConfigurationException::missingAuditDriver($driver);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidConfigurationException::class);
            expect($exception->getMessage())->toBe("Audit driver 'elasticsearch' is not configured. Add it to the 'audit_drivers' configuration.");
        });

        test('creates exception for invalid morph type', function (): void {
            // Arrange
            $type = 'NonExistentClass';

            // Act
            $exception = InvalidConfigurationException::invalidMorphType($type);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidConfigurationException::class);
            expect($exception->getMessage())->toBe("Invalid morph type 'NonExistentClass'. Ensure the class exists and is properly configured.");
        });
    });
});

describe('InvalidEnvironmentException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for unknown environment', function (): void {
            // Arrange
            $environment = 'staging';

            // Act
            $exception = InvalidEnvironmentException::unknown($environment);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidEnvironmentException::class);
            expect($exception->getMessage())->toBe('Unknown environment: staging');
        });

        test('creates exception for not allowed environment', function (): void {
            // Arrange
            $environment = 'production';
            $allowed = ['test', 'live'];

            // Act
            $exception = InvalidEnvironmentException::notAllowed($environment, $allowed);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidEnvironmentException::class);
            expect($exception->getMessage())->toBe("Environment 'production' is not allowed. Allowed environments: test, live");
        });

        test('handles single allowed environment', function (): void {
            // Arrange
            $environment = 'test';
            $allowed = ['live'];

            // Act
            $exception = InvalidEnvironmentException::notAllowed($environment, $allowed);

            // Assert
            expect($exception->getMessage())->toContain('Allowed environments: live');
        });
    });
});

describe('InvalidPrimaryKeyValueException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for non-string UUID', function (): void {
            // Arrange
            $value = 12_345;

            // Act
            $exception = InvalidPrimaryKeyValueException::nonStringUuid($value);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidPrimaryKeyValueException::class);
            expect($exception->getMessage())->toBe('Cannot assign non-string value to UUID primary key. Got: integer');
        });

        test('creates exception for non-string ULID', function (): void {
            // Arrange
            $value = ['array', 'value'];

            // Act
            $exception = InvalidPrimaryKeyValueException::nonStringUlid($value);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidPrimaryKeyValueException::class);
            expect($exception->getMessage())->toBe('Cannot assign non-string value to ULID primary key. Got: array');
        });

        test('handles different value types for UUID', function (): void {
            // Arrange & Act
            $intException = InvalidPrimaryKeyValueException::nonStringUuid(123);
            $floatException = InvalidPrimaryKeyValueException::nonStringUuid(12.34);
            $boolException = InvalidPrimaryKeyValueException::nonStringUuid(true);
            $nullException = InvalidPrimaryKeyValueException::nonStringUuid(null);

            // Assert
            expect($intException->getMessage())->toContain('Got: integer');
            expect($floatException->getMessage())->toContain('Got: double');
            expect($boolException->getMessage())->toContain('Got: boolean');
            expect($nullException->getMessage())->toContain('Got: NULL');
        });

        test('handles different value types for ULID', function (): void {
            // Arrange & Act
            $intException = InvalidPrimaryKeyValueException::nonStringUlid(456);
            $objectException = InvalidPrimaryKeyValueException::nonStringUlid((object) ['key' => 'value']);

            // Assert
            expect($intException->getMessage())->toContain('Got: integer');
            expect($objectException->getMessage())->toContain('Got: object');
        });
    });
});

describe('InvalidTokenTypeException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for unknown token type', function (): void {
            // Arrange
            $type = 'unknown';

            // Act
            $exception = InvalidTokenTypeException::unknown($type);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidTokenTypeException::class);
            expect($exception->getMessage())->toBe('Unknown token type: unknown');
        });

        test('creates exception for not registered token type', function (): void {
            // Arrange
            $type = 'custom';

            // Act
            $exception = InvalidTokenTypeException::notRegistered($type);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidTokenTypeException::class);
            expect($exception->getMessage())->toBe("Token type 'custom' is not registered in the configuration.");
        });

        test('creates exception for token type not allowed for request', function (): void {
            // Arrange
            $currentType = 'personal';
            $allowedTypes = ['admin', 'service'];

            // Act
            $exception = InvalidTokenTypeException::notAllowedForRequest($currentType, $allowedTypes);

            // Assert
            expect($exception)->toBeInstanceOf(InvalidTokenTypeException::class);
            expect($exception->getMessage())->toBe("Token type 'personal' is not allowed. Allowed types: admin, service");
        });

        test('handles single allowed type for request', function (): void {
            // Arrange
            $currentType = 'personal';
            $allowedTypes = ['admin'];

            // Act
            $exception = InvalidTokenTypeException::notAllowedForRequest($currentType, $allowedTypes);

            // Assert
            expect($exception->getMessage())->toContain('Allowed types: admin');
        });

        test('handles multiple allowed types for request', function (): void {
            // Arrange
            $currentType = 'guest';
            $allowedTypes = ['admin', 'service', 'application'];

            // Act
            $exception = InvalidTokenTypeException::notAllowedForRequest($currentType, $allowedTypes);

            // Assert
            expect($exception->getMessage())->toContain('admin, service, application');
        });
    });
});

describe('IpRestrictionException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception with notAllowed factory method', function (): void {
            // Arrange
            $ip = '192.168.1.100';
            $allowedIps = ['10.0.0.0/8', '192.168.1.1'];

            // Act
            $exception = IpRestrictionException::notAllowed($ip, $allowedIps);

            // Assert
            expect($exception)->toBeInstanceOf(IpRestrictionException::class);
            expect($exception->getMessage())->toBe("IP address '192.168.1.100' is not allowed. Allowed IPs: 10.0.0.0/8, 192.168.1.1");
        });

        test('handles single allowed IP', function (): void {
            // Arrange
            $ip = '8.8.8.8';
            $allowedIps = ['192.168.1.1'];

            // Act
            $exception = IpRestrictionException::notAllowed($ip, $allowedIps);

            // Assert
            expect($exception->getMessage())->toContain('Allowed IPs: 192.168.1.1');
        });

        test('handles IPv6 addresses', function (): void {
            // Arrange
            $ip = '2001:db8::1';
            $allowedIps = ['fe80::/10', '2001:db8::/32'];

            // Act
            $exception = IpRestrictionException::notAllowed($ip, $allowedIps);

            // Assert
            expect($exception->getMessage())->toContain('2001:db8::1');
            expect($exception->getMessage())->toContain('fe80::/10, 2001:db8::/32');
        });

        test('creates exception with forIp factory method', function (): void {
            // Arrange
            $ip = '203.0.113.42';

            // Act
            $exception = IpRestrictionException::forIp($ip);

            // Assert
            expect($exception)->toBeInstanceOf(IpRestrictionException::class);
            expect($exception->getMessage())->toBe('IP address 203.0.113.42 is not allowed for this token.');
        });
    });
});

describe('MissingAbilityException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for missing single ability', function (): void {
            // Arrange
            $ability = 'delete:posts';

            // Act
            $exception = MissingAbilityException::missing($ability);

            // Assert
            expect($exception)->toBeInstanceOf(MissingAbilityException::class);
            expect($exception->getMessage())->toBe('Token is missing required ability: delete:posts');
        });

        test('creates exception for missing any of multiple abilities', function (): void {
            // Arrange
            $abilities = ['read:users', 'write:users', 'delete:users'];

            // Act
            $exception = MissingAbilityException::missingAny($abilities);

            // Assert
            expect($exception)->toBeInstanceOf(MissingAbilityException::class);
            expect($exception->getMessage())->toBe('Token is missing any of the required abilities: read:users, write:users, delete:users');
        });

        test('handles single ability in array', function (): void {
            // Arrange
            $abilities = ['admin'];

            // Act
            $exception = MissingAbilityException::missingAny($abilities);

            // Assert
            expect($exception->getMessage())->toContain('admin');
        });
    });
});

describe('RateLimitExceededException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception with limit and retry time', function (): void {
            // Arrange
            $limit = 100;
            $retryAfter = 60;

            // Act
            $exception = RateLimitExceededException::forToken($limit, $retryAfter);

            // Assert
            expect($exception)->toBeInstanceOf(RateLimitExceededException::class);
            expect($exception->getMessage())->toBe('Rate limit of 100 requests exceeded. Retry after 60 seconds.');
        });

        test('provides retry after seconds', function (): void {
            // Arrange
            $limit = 1_000;
            $retryAfter = 120;

            // Act
            $exception = RateLimitExceededException::forToken($limit, $retryAfter);

            // Assert
            expect($exception->retryAfter())->toBe(120);
        });

        test('handles different limit values', function (): void {
            // Arrange & Act
            $lowLimit = RateLimitExceededException::forToken(10, 30);
            $highLimit = RateLimitExceededException::forToken(10_000, 300);

            // Assert
            expect($lowLimit->getMessage())->toContain('10 requests');
            expect($lowLimit->retryAfter())->toBe(30);
            expect($highLimit->getMessage())->toContain('10000 requests');
            expect($highLimit->retryAfter())->toBe(300);
        });
    });
});

describe('TokenExpiredException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception with expiration timestamp', function (): void {
            // Arrange
            $expiredAt = Date::parse('2024-01-15 10:30:00');

            // Act
            $exception = TokenExpiredException::at($expiredAt);

            // Assert
            expect($exception)->toBeInstanceOf(TokenExpiredException::class);
            expect($exception->getMessage())->toBe('Token expired at 2024-01-15 10:30:00');
        });

        test('formats date correctly', function (): void {
            // Arrange
            $expiredAt = Date::parse('2025-12-31 23:59:59');

            // Act
            $exception = TokenExpiredException::at($expiredAt);

            // Assert
            expect($exception->getMessage())->toContain('2025-12-31 23:59:59');
        });

        test('works with DateTimeImmutable', function (): void {
            // Arrange
            $expiredAt = CarbonImmutable::parse('2024-06-15 14:20:30');

            // Act
            $exception = TokenExpiredException::at($expiredAt);

            // Assert
            expect($exception->getMessage())->toBe('Token expired at 2024-06-15 14:20:30');
        });

        test('creates exception without timestamp', function (): void {
            // Arrange & Act
            $exception = TokenExpiredException::expired();

            // Assert
            expect($exception)->toBeInstanceOf(TokenExpiredException::class);
            expect($exception->getMessage())->toBe('This token has expired.');
        });
    });
});

describe('TokenNotFoundException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for prefix not found', function (): void {
            // Arrange
            $prefix = 'sk_test_abc123';

            // Act
            $exception = TokenNotFoundException::forPrefix($prefix);

            // Assert
            expect($exception)->toBeInstanceOf(TokenNotFoundException::class);
            expect($exception->getMessage())->toBe("Token with prefix 'sk_test_abc123' not found.");
        });

        test('creates exception for numeric ID not found', function (): void {
            // Arrange
            $id = 12_345;

            // Act
            $exception = TokenNotFoundException::forId($id);

            // Assert
            expect($exception)->toBeInstanceOf(TokenNotFoundException::class);
            expect($exception->getMessage())->toBe("Token with ID '12345' not found.");
        });

        test('creates exception for string ID not found', function (): void {
            // Arrange
            $id = '550e8400-e29b-41d4-a716-446655440000';

            // Act
            $exception = TokenNotFoundException::forId($id);

            // Assert
            expect($exception)->toBeInstanceOf(TokenNotFoundException::class);
            expect($exception->getMessage())->toBe("Token with ID '550e8400-e29b-41d4-a716-446655440000' not found.");
        });
    });
});

describe('TokenRevokedException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception with revocation timestamp', function (): void {
            // Arrange
            $revokedAt = Date::parse('2024-02-20 15:45:30');

            // Act
            $exception = TokenRevokedException::at($revokedAt);

            // Assert
            expect($exception)->toBeInstanceOf(TokenRevokedException::class);
            expect($exception->getMessage())->toBe('Token was revoked at 2024-02-20 15:45:30');
        });

        test('formats date correctly', function (): void {
            // Arrange
            $revokedAt = Date::parse('2025-01-01 00:00:00');

            // Act
            $exception = TokenRevokedException::at($revokedAt);

            // Assert
            expect($exception->getMessage())->toContain('2025-01-01 00:00:00');
        });

        test('works with DateTimeImmutable', function (): void {
            // Arrange
            $revokedAt = CarbonImmutable::parse('2024-11-26 12:00:00');

            // Act
            $exception = TokenRevokedException::at($revokedAt);

            // Assert
            expect($exception->getMessage())->toBe('Token was revoked at 2024-11-26 12:00:00');
        });

        test('creates exception without timestamp', function (): void {
            // Arrange & Act
            $exception = TokenRevokedException::revoked();

            // Assert
            expect($exception)->toBeInstanceOf(TokenRevokedException::class);
            expect($exception->getMessage())->toBe('This token has been revoked.');
        });
    });
});

describe('TokenGeneratorNotRegisteredException', function (): void {
    describe('Happy Path', function (): void {
        test('creates exception for generator not found by name', function (): void {
            // Arrange
            $name = 'custom-generator';

            // Act
            $exception = TokenGeneratorNotRegisteredException::forName($name);

            // Assert
            expect($exception)->toBeInstanceOf(TokenGeneratorNotRegisteredException::class);
            expect($exception->getMessage())->toBe('Token generator "custom-generator" is not registered.');
        });

        test('creates exception for no default generator', function (): void {
            // Arrange & Act
            $exception = TokenGeneratorNotRegisteredException::noDefault();

            // Assert
            expect($exception)->toBeInstanceOf(TokenGeneratorNotRegisteredException::class);
            expect($exception->getMessage())->toBe('No default token generator is registered.');
        });

        test('creates exception when cannot set unregistered generator as default', function (): void {
            // Arrange
            $name = 'unregistered-generator';

            // Act
            $exception = TokenGeneratorNotRegisteredException::cannotSetAsDefault($name);

            // Assert
            expect($exception)->toBeInstanceOf(TokenGeneratorNotRegisteredException::class);
            expect($exception->getMessage())->toBe('Cannot set unregistered generator "unregistered-generator" as default.');
        });

        test('handles different generator names', function (): void {
            // Arrange & Act
            $exception1 = TokenGeneratorNotRegisteredException::forName('uuid-v4');
            $exception2 = TokenGeneratorNotRegisteredException::forName('nanoid');
            $exception3 = TokenGeneratorNotRegisteredException::forName('custom');

            // Assert
            expect($exception1->getMessage())->toContain('uuid-v4');
            expect($exception2->getMessage())->toContain('nanoid');
            expect($exception3->getMessage())->toContain('custom');
        });
    });
});
