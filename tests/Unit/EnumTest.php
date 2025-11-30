<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Enums\Environment;
use Cline\Bearer\Enums\MorphType;
use Cline\Bearer\Enums\PrimaryKeyType;

describe('AuditEvent', function (): void {
    describe('Happy Path', function (): void {
        test('has created case', function (): void {
            // Act & Assert
            expect(AuditEvent::Created->value)->toBe('created');
        });

        test('has authenticated case', function (): void {
            // Act & Assert
            expect(AuditEvent::Authenticated->value)->toBe('authenticated');
        });

        test('has revoked case', function (): void {
            // Act & Assert
            expect(AuditEvent::Revoked->value)->toBe('revoked');
        });

        test('has rotated case', function (): void {
            // Act & Assert
            expect(AuditEvent::Rotated->value)->toBe('rotated');
        });

        test('has failed case', function (): void {
            // Act & Assert
            expect(AuditEvent::Failed->value)->toBe('failed');
        });

        test('has rate limited case', function (): void {
            // Act & Assert
            expect(AuditEvent::RateLimited->value)->toBe('rate_limited');
        });

        test('has ip blocked case', function (): void {
            // Act & Assert
            expect(AuditEvent::IpBlocked->value)->toBe('ip_blocked');
        });

        test('has domain blocked case', function (): void {
            // Act & Assert
            expect(AuditEvent::DomainBlocked->value)->toBe('domain_blocked');
        });

        test('has expired case', function (): void {
            // Act & Assert
            expect(AuditEvent::Expired->value)->toBe('expired');
        });

        test('has all expected cases', function (): void {
            // Act
            $cases = AuditEvent::cases();

            // Assert
            expect($cases)->toHaveCount(10);
            expect($cases)->toContain(AuditEvent::Created);
            expect($cases)->toContain(AuditEvent::Authenticated);
            expect($cases)->toContain(AuditEvent::Revoked);
            expect($cases)->toContain(AuditEvent::Rotated);
            expect($cases)->toContain(AuditEvent::Failed);
            expect($cases)->toContain(AuditEvent::RateLimited);
            expect($cases)->toContain(AuditEvent::IpBlocked);
            expect($cases)->toContain(AuditEvent::DomainBlocked);
            expect($cases)->toContain(AuditEvent::Expired);
            expect($cases)->toContain(AuditEvent::Derived);
        });

        test('can create from value', function (): void {
            // Act
            $event = AuditEvent::from('created');

            // Assert
            expect($event)->toBe(AuditEvent::Created);
        });

        test('can try from value', function (): void {
            // Act
            $valid = AuditEvent::tryFrom('authenticated');
            $invalid = AuditEvent::tryFrom('nonexistent');

            // Assert
            expect($valid)->toBe(AuditEvent::Authenticated);
            expect($invalid)->toBeNull();
        });
    });
});

describe('Environment', function (): void {
    describe('Happy Path', function (): void {
        test('has test case', function (): void {
            // Act & Assert
            expect(Environment::Test->value)->toBe('test');
        });

        test('has live case', function (): void {
            // Act & Assert
            expect(Environment::Live->value)->toBe('live');
        });

        test('has all expected cases', function (): void {
            // Act
            $cases = Environment::cases();

            // Assert
            expect($cases)->toHaveCount(2);
            expect($cases)->toContain(Environment::Test);
            expect($cases)->toContain(Environment::Live);
        });

        test('prefix returns correct value for test', function (): void {
            // Act
            $prefix = Environment::Test->prefix();

            // Assert
            expect($prefix)->toBe('test');
        });

        test('prefix returns correct value for live', function (): void {
            // Act
            $prefix = Environment::Live->prefix();

            // Assert
            expect($prefix)->toBe('live');
        });

        test('can create from value', function (): void {
            // Act
            $test = Environment::from('test');
            $live = Environment::from('live');

            // Assert
            expect($test)->toBe(Environment::Test);
            expect($live)->toBe(Environment::Live);
        });

        test('can try from value', function (): void {
            // Act
            $valid = Environment::tryFrom('test');
            $invalid = Environment::tryFrom('staging');

            // Assert
            expect($valid)->toBe(Environment::Test);
            expect($invalid)->toBeNull();
        });
    });
});

describe('MorphType', function (): void {
    describe('Happy Path', function (): void {
        test('has numeric case', function (): void {
            // Act & Assert
            expect(MorphType::Numeric->value)->toBe('numeric');
        });

        test('has uuid case', function (): void {
            // Act & Assert
            expect(MorphType::UUID->value)->toBe('uuid');
        });

        test('has ulid case', function (): void {
            // Act & Assert
            expect(MorphType::ULID->value)->toBe('ulid');
        });

        test('has string case', function (): void {
            // Act & Assert
            expect(MorphType::String->value)->toBe('string');
        });

        test('has all expected cases', function (): void {
            // Act
            $cases = MorphType::cases();

            // Assert
            expect($cases)->toHaveCount(4);
            expect($cases)->toContain(MorphType::Numeric);
            expect($cases)->toContain(MorphType::UUID);
            expect($cases)->toContain(MorphType::ULID);
            expect($cases)->toContain(MorphType::String);
        });

        test('can create from value', function (): void {
            // Act
            $numeric = MorphType::from('numeric');
            $uuid = MorphType::from('uuid');
            $ulid = MorphType::from('ulid');
            $string = MorphType::from('string');

            // Assert
            expect($numeric)->toBe(MorphType::Numeric);
            expect($uuid)->toBe(MorphType::UUID);
            expect($ulid)->toBe(MorphType::ULID);
            expect($string)->toBe(MorphType::String);
        });

        test('can try from value', function (): void {
            // Act
            $valid = MorphType::tryFrom('uuid');
            $invalid = MorphType::tryFrom('custom');

            // Assert
            expect($valid)->toBe(MorphType::UUID);
            expect($invalid)->toBeNull();
        });
    });
});

describe('PrimaryKeyType', function (): void {
    describe('Happy Path', function (): void {
        test('has id case', function (): void {
            // Act & Assert
            expect(PrimaryKeyType::Id->value)->toBe('id');
        });

        test('has uuid case', function (): void {
            // Act & Assert
            expect(PrimaryKeyType::UUID->value)->toBe('uuid');
        });

        test('has ulid case', function (): void {
            // Act & Assert
            expect(PrimaryKeyType::ULID->value)->toBe('ulid');
        });

        test('has all expected cases', function (): void {
            // Act
            $cases = PrimaryKeyType::cases();

            // Assert
            expect($cases)->toHaveCount(3);
            expect($cases)->toContain(PrimaryKeyType::Id);
            expect($cases)->toContain(PrimaryKeyType::UUID);
            expect($cases)->toContain(PrimaryKeyType::ULID);
        });

        test('can create from value', function (): void {
            // Act
            $id = PrimaryKeyType::from('id');
            $uuid = PrimaryKeyType::from('uuid');
            $ulid = PrimaryKeyType::from('ulid');

            // Assert
            expect($id)->toBe(PrimaryKeyType::Id);
            expect($uuid)->toBe(PrimaryKeyType::UUID);
            expect($ulid)->toBe(PrimaryKeyType::ULID);
        });

        test('can try from value', function (): void {
            // Act
            $valid = PrimaryKeyType::tryFrom('uuid');
            $invalid = PrimaryKeyType::tryFrom('bigint');

            // Assert
            expect($valid)->toBe(PrimaryKeyType::UUID);
            expect($invalid)->toBeNull();
        });
    });
});
