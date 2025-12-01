<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Concerns\HasAccessTokens;
use Cline\Bearer\Facades\Bearer;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\Fixtures\User;

uses(RefreshDatabase::class);

// Create a simple mock model for context/boundary testing
/**
 * @author Brian Faust <brian@cline.sh>
 */
final class ServiceAccount extends Model
{
    use HasFactory;
    use HasAccessTokens;

    protected $table = 'service_accounts';

    protected $guarded = [];
}

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class Team extends Model
{
    use HasFactory;
    use HasAccessTokens;

    protected $table = 'teams';

    protected $guarded = [];
}

beforeEach(function (): void {
    // Create service_accounts and teams tables for testing
    $this->app['db']->connection()->getSchemaBuilder()->create('service_accounts', function ($table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
    });

    $this->app['db']->connection()->getSchemaBuilder()->create('teams', function ($table): void {
        $table->id();
        $table->string('name');
        $table->timestamps();
    });
});

describe('Token Owner Relationship', function (): void {
    it('creates token with owner relationship', function (): void {
        $user = createUser();

        $token = Bearer::for($user)->issue('sk', 'Test Token');

        expect($token->accessToken->owner_type)->toBe(User::class);
        expect($token->accessToken->owner_id)->toBe($user->id);
        expect($token->accessToken->owner->id)->toBe($user->id);
    });

    it('queries tokens by owner', function (): void {
        $user = createUser();

        Bearer::for($user)->issue('sk', 'Token 1');
        Bearer::for($user)->issue('pk', 'Token 2');

        expect($user->accessTokens()->count())->toBe(2);
    });
});

describe('Token Context Relationship', function (): void {
    it('creates token with context relationship', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);

        $token = Bearer::for($user)
            ->context($serviceAccount)
            ->issue('sk', 'Service Token');

        expect($token->accessToken->owner_type)->toBe(User::class);
        expect($token->accessToken->owner_id)->toBe($user->id);
        expect($token->accessToken->context_type)->toBe(ServiceAccount::class);
        expect($token->accessToken->context_id)->toBe($serviceAccount->id);
        expect($token->accessToken->context->id)->toBe($serviceAccount->id);
    });

    it('creates token without context (null)', function (): void {
        $user = createUser();

        $token = Bearer::for($user)->issue('sk', 'No Context Token');

        expect($token->accessToken->context_type)->toBeNull();
        expect($token->accessToken->context_id)->toBeNull();
        expect($token->accessToken->context)->toBeNull();
    });

    it('queries tokens by context', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);

        Bearer::for($user)->context($serviceAccount)->issue('sk', 'Token 1');
        Bearer::for($user)->context($serviceAccount)->issue('pk', 'Token 2');
        Bearer::for($user)->issue('rk', 'Token without context');

        expect($serviceAccount->contextTokens()->count())->toBe(2);
    });
});

describe('Token Boundary Relationship', function (): void {
    it('creates token with boundary relationship', function (): void {
        $user = createUser();
        $team = Team::query()->create(['name' => 'Test Team']);

        $token = Bearer::for($user)
            ->boundary($team)
            ->issue('sk', 'Team Token');

        expect($token->accessToken->owner_type)->toBe(User::class);
        expect($token->accessToken->owner_id)->toBe($user->id);
        expect($token->accessToken->boundary_type)->toBe(Team::class);
        expect($token->accessToken->boundary_id)->toBe($team->id);
        expect($token->accessToken->boundary->id)->toBe($team->id);
    });

    it('creates token without boundary (null)', function (): void {
        $user = createUser();

        $token = Bearer::for($user)->issue('sk', 'No Boundary Token');

        expect($token->accessToken->boundary_type)->toBeNull();
        expect($token->accessToken->boundary_id)->toBeNull();
        expect($token->accessToken->boundary)->toBeNull();
    });

    it('queries tokens by boundary', function (): void {
        $user = createUser();
        $team = Team::query()->create(['name' => 'Test Team']);

        Bearer::for($user)->boundary($team)->issue('sk', 'Token 1');
        Bearer::for($user)->boundary($team)->issue('pk', 'Token 2');
        Bearer::for($user)->issue('rk', 'Token without boundary');

        expect($team->boundaryTokens()->count())->toBe(2);
    });
});

describe('Full Three-Tier Relationships', function (): void {
    it('creates token with owner, context, and boundary', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);
        $team = Team::query()->create(['name' => 'Test Team']);

        $token = Bearer::for($user)
            ->context($serviceAccount)
            ->boundary($team)
            ->issue('sk', 'Full Token');

        expect($token->accessToken->owner->id)->toBe($user->id);
        expect($token->accessToken->context->id)->toBe($serviceAccount->id);
        expect($token->accessToken->boundary->id)->toBe($team->id);
    });

    it('preserves all relationships during token rotation', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);
        $team = Team::query()->create(['name' => 'Test Team']);

        $originalToken = Bearer::for($user)
            ->context($serviceAccount)
            ->boundary($team)
            ->issue('sk', 'Original Token');

        $rotatedToken = Bearer::rotate($originalToken->accessToken);

        expect($rotatedToken->accessToken->owner_id)->toBe($originalToken->accessToken->owner_id);
        expect($rotatedToken->accessToken->context_type)->toBe($originalToken->accessToken->context_type);
        expect($rotatedToken->accessToken->context_id)->toBe($originalToken->accessToken->context_id);
        expect($rotatedToken->accessToken->boundary_type)->toBe($originalToken->accessToken->boundary_type);
        expect($rotatedToken->accessToken->boundary_id)->toBe($originalToken->accessToken->boundary_id);
    });

    it('applies relationships to token groups', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);
        $team = Team::query()->create(['name' => 'Test Team']);

        $group = Bearer::for($user)
            ->context($serviceAccount)
            ->boundary($team)
            ->issueGroup(['sk', 'pk'], 'Group Tokens');

        foreach ($group->accessTokens as $token) {
            expect($token->owner_id)->toBe($user->id);
            expect($token->context_type)->toBe(ServiceAccount::class);
            expect($token->context_id)->toBe($serviceAccount->id);
            expect($token->boundary_type)->toBe(Team::class);
            expect($token->boundary_id)->toBe($team->id);
        }
    });
});

describe('Conductor Method Chaining', function (): void {
    it('chains context after abilities', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);

        $token = Bearer::for($user)
            ->abilities(['api:read'])
            ->context($serviceAccount)
            ->issue('sk', 'Chained Token');

        expect($token->accessToken->abilities)->toBe(['api:read']);
        expect($token->accessToken->context_id)->toBe($serviceAccount->id);
    });

    it('chains boundary after context', function (): void {
        $user = createUser();
        $serviceAccount = ServiceAccount::query()->create(['name' => 'Test Service']);
        $team = Team::query()->create(['name' => 'Test Team']);

        $token = Bearer::for($user)
            ->context($serviceAccount)
            ->boundary($team)
            ->rateLimit(100)
            ->issue('sk', 'Full Chain Token');

        expect($token->accessToken->context_id)->toBe($serviceAccount->id);
        expect($token->accessToken->boundary_id)->toBe($team->id);
        expect($token->accessToken->rate_limit_per_minute)->toBe(100);
    });
});
