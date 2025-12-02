<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Conductors\TokenDerivationConductor;
use Cline\Bearer\Conductors\TokenRevocationConductor;
use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Enums\AuditEvent;
use Cline\Bearer\Exceptions\CannotDeriveTokenException;
use Cline\Bearer\Exceptions\InvalidDerivedAbilitiesException;
use Cline\Bearer\Exceptions\InvalidDerivedExpirationException;
use Cline\Bearer\Facades\Bearer;

use function Pest\Laravel\assertDatabaseHas;

describe('Token Derivation', function (): void {
    test('can derive token from parent', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent Token', abilities: ['users:read', 'users:write']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child Token');

        expect($childToken->accessToken)->toBeInstanceOf(AccessToken::class)
            ->and($childToken->accessToken->abilities)->toBe(['users:read'])
            ->and($childToken->accessToken->parentToken()->id)->toBe($parentToken->accessToken->id)
            ->and($childToken->plainTextAccessToken)->toBeString();
    });

    test('derived token inherits parent restrictions', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)
            ->allowedIps(['192.168.1.1'])
            ->allowedDomains(['example.com'])
            ->rateLimit(100)
            ->issue('sk', 'Parent Token', abilities: ['*']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child Token');

        expect($childToken->accessToken->allowed_ips)->toBe(['192.168.1.1'])
            ->and($childToken->accessToken->allowed_domains)->toBe(['example.com'])
            ->and($childToken->accessToken->rate_limit_per_minute)->toBe(100);
    });

    test('can derive multiple children from one parent', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent Token', abilities: ['*']);

        $child1 = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child 1');

        $child2 = Bearer::derive($parentToken->accessToken)
            ->abilities(['posts:read'])
            ->as('Child 2');

        expect($parentToken->accessToken->childTokens())->toHaveCount(2)
            ->and($child1->accessToken->parentToken()->id)->toBe($parentToken->accessToken->id)
            ->and($child2->accessToken->parentToken()->id)->toBe($parentToken->accessToken->id);
    });

    test('can derive nested tokens (grandchildren)', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['users:read', 'posts:read']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read', 'posts:read'])
            ->as('Child');

        $grandchildToken = Bearer::derive($childToken->accessToken)
            ->abilities(['users:read'])
            ->as('Grandchild');

        expect($grandchildToken->accessToken->parentToken()->id)->toBe($childToken->accessToken->id)
            ->and($childToken->accessToken->parentToken()->id)->toBe($parentToken->accessToken->id)
            ->and($parentToken->accessToken->allDescendantTokens())->toHaveCount(2);
    });

    test('throws exception when parent is revoked', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);
        $parentToken->accessToken->revoke();

        expect(fn (): mixed => Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child'))->toThrow(CannotDeriveTokenException::class);
    });

    test('throws exception when parent is expired', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->expiresIn(1)->issue('sk', 'Parent', abilities: ['*']);

        $parentToken->accessToken->update(['expires_at' => now()->subDay()]);

        expect(fn (): mixed => Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child'))->toThrow(CannotDeriveTokenException::class);
    });

    test('throws exception when child abilities exceed parent abilities', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['users:read']);

        expect(fn (): mixed => Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read', 'users:write'])
            ->as('Child'))->toThrow(InvalidDerivedAbilitiesException::class);
    });

    test('throws exception when child expiration exceeds parent expiration', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->expiresAt(now()->addDays(7))->issue('sk', 'Parent', abilities: ['*']);

        expect(fn (): mixed => Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->expiresAt(now()->addDays(14))
            ->as('Child'))->toThrow(InvalidDerivedExpirationException::class);
    });

    test('respects maximum derivation depth', function (): void {
        config(['bearer.derivation.max_depth' => 2]);

        $user = createUser();

        $level0 = Bearer::for($user)->issue('sk', 'Level 0', abilities: ['*']);
        $level1 = Bearer::derive($level0->accessToken)->abilities(['*'])->as('Level 1');
        $level2 = Bearer::derive($level1->accessToken)->abilities(['*'])->as('Level 2');

        expect(fn (): mixed => Bearer::derive($level2->accessToken)
            ->abilities(['*'])
            ->as('Level 3'))->toThrow(CannotDeriveTokenException::class);
    });

    test('stores derived metadata', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->metadata([
                'reseller_id' => 'res_123',
                'customer_id' => 'cust_456',
            ])
            ->as('Child');

        expect($childToken->accessToken->derived_metadata)->toBe([
            'reseller_id' => 'res_123',
            'customer_id' => 'cust_456',
        ]);
    });

    test('logs derived audit event', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child');

        assertDatabaseHas('access_token_audit_logs', [
            'token_id' => $childToken->accessToken->id,
            'event' => AuditEvent::Derived->value,
        ]);
    });

    test('cascade descendants revocation strategy revokes all descendants', function (): void {
        $user = createUser();

        $parent = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);
        $child1 = Bearer::derive($parent->accessToken)->abilities(['*'])->as('Child 1');
        $child2 = Bearer::derive($parent->accessToken)->abilities(['*'])->as('Child 2');
        $grandchild = Bearer::derive($child1->accessToken)->abilities(['*'])->as('Grandchild');

        Bearer::revoke($parent->accessToken)->withDescendants();

        expect($parent->accessToken->fresh()->isRevoked())->toBeTrue()
            ->and($child1->accessToken->fresh()->isRevoked())->toBeTrue()
            ->and($child2->accessToken->fresh()->isRevoked())->toBeTrue()
            ->and($grandchild->accessToken->fresh()->isRevoked())->toBeTrue();
    });

    test('can check if token is root', function (): void {
        $user = createUser();

        $parent = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);
        $child = Bearer::derive($parent->accessToken)->abilities(['*'])->as('Child');

        expect($parent->accessToken->isRootToken())->toBeTrue()
            ->and($child->accessToken->isRootToken())->toBeFalse();
    });

    test('can check if token can derive', function (): void {
        $user = createUser();

        $validToken = Bearer::for($user)->issue('sk', 'Valid', abilities: ['*']);
        $revokedToken = Bearer::for($user)->issue('sk', 'Revoked', abilities: ['*']);
        $revokedToken->accessToken->revoke();

        expect($validToken->accessToken->canDeriveTokens())->toBeTrue()
            ->and($revokedToken->accessToken->canDeriveTokens())->toBeFalse();
    });

    test('parent and child use same environment', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->environment('live')->issue('sk', 'Parent', abilities: ['*']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->as('Child');

        expect($childToken->accessToken->environment)->toBe('live')
            ->and($childToken->accessToken->environment)->toBe($parentToken->accessToken->environment);
    });

    test('can derive with expiresIn helper', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read'])
            ->expiresIn(3_600) // 1 hour
            ->as('Child');

        expect($childToken->accessToken->expires_at)->not->toBeNull()
            ->and($childToken->accessToken->expires_at->isFuture())->toBeTrue()
            ->and(now()->diffInSeconds($childToken->accessToken->expires_at))->toBeGreaterThanOrEqual(3_599)
            ->and(now()->diffInSeconds($childToken->accessToken->expires_at))->toBeLessThanOrEqual(3_601);
    });

    test('fluent API methods are chainable', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)
            ->allowedIps(['192.168.1.1'])
            ->allowedDomains(['example.com'])
            ->rateLimit(100)
            ->issue('sk', 'Parent', abilities: ['users:read', 'users:write', 'posts:read']);

        $childToken = Bearer::derive($parentToken->accessToken)
            ->abilities(['users:read', 'posts:read'])
            ->metadata(['customer_id' => 'cust_123', 'plan' => 'premium'])
            ->expiresAt(now()->addDays(30))
            ->as('Customer Token');

        expect($childToken->accessToken->abilities)->toBe(['users:read', 'posts:read'])
            ->and($childToken->accessToken->derived_metadata)->toBe(['customer_id' => 'cust_123', 'plan' => 'premium'])
            ->and($childToken->accessToken->expires_at)->not->toBeNull()
            ->and($childToken->accessToken->allowed_ips)->toBe(['192.168.1.1']) // Inherited
            ->and($childToken->accessToken->allowed_domains)->toBe(['example.com']) // Inherited
            ->and($childToken->accessToken->rate_limit_per_minute)->toBe(100); // Inherited
    });

    test('revoke API returns conductor', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);

        $conductor = Bearer::revoke($parentToken->accessToken);

        expect($conductor)->toBeInstanceOf(TokenRevocationConductor::class);
    });

    test('derive API returns conductor', function (): void {
        $user = createUser();

        $parentToken = Bearer::for($user)->issue('sk', 'Parent', abilities: ['*']);

        $conductor = Bearer::derive($parentToken->accessToken);

        expect($conductor)->toBeInstanceOf(TokenDerivationConductor::class);
    });
});
