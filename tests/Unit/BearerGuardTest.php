<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Events\TokenAuthenticated;
use Cline\Bearer\Exceptions\TokenExpiredException;
use Cline\Bearer\Exceptions\TokenRevokedException;
use Cline\Bearer\TransientToken;
use Illuminate\Contracts\Auth\Factory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Tests\Fixtures\User;
use Tests\Fixtures\UserWithoutTokens;

function createRawToken(Authenticatable $user, array $attributes): AccessToken
{
    $defaults = [
        'type' => 'secret_key',
        'environment' => 'testing',
        'name' => 'Test Token',
        'prefix' => 'sk_test',
        'tokenable_type' => User::class,
        'tokenable_id' => $user->id,
    ];

    return Model::unguarded(fn () => AccessToken::query()->create(array_merge($defaults, $attributes)));
}

describe('BearerGuard', function (): void {
    beforeEach(function (): void {
        Config::set('auth.providers.users.model', User::class);
        Config::set('app.key', 'base64:'.base64_encode(random_bytes(32)));

        Route::middleware(['auth:bearer'])->get('/test-auth', fn () => response()->json([
            'user_id' => Auth::id(),
            'token_type' => Auth::user()?->currentAccessToken() ? Auth::user()->currentAccessToken()::class : null,
        ]));

        // Define login route to prevent RouteNotFoundException
        Route::get('/login', fn () => response()->json(['error' => 'Unauthenticated'], 401))->name('login');
    });

    describe('Happy Path', function (): void {
        test('returns user from stateful guard when authenticated via session', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);

            $response = $this->actingAs($user, 'web')->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
            expect($response->json('token_type'))->toBe(TransientToken::class);
        });

        test('validates bearer token and returns user with token attached', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'test-token-'.uniqid();
            $token = createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'abilities' => ['read', 'write'],
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
            expect($response->json('token_type'))->toBe(AccessToken::class);

            Event::assertDispatched(TokenAuthenticated::class);

            $token->refresh();
            expect($token->last_used_at)->not->toBeNull();
        });

        test('updates last_used_at timestamp on authentication', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'last-used-token-'.uniqid();
            $token = createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'last_used_at' => null,
            ]);

            $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth');

            $token->refresh();
            expect($token->last_used_at)->not->toBeNull();
        });

        test('dispatches TokenAuthenticated event with request details', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'event-token-'.uniqid();
            createRawToken($user, ['token' => hash('sha256', $plainToken)]);

            $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'User-Agent' => 'Test Agent',
            ])->get('/test-auth');

            Event::assertDispatched(TokenAuthenticated::class, fn ($event): bool => $event->token->tokenable_id === $user->id
                && $event->userAgent === 'Test Agent');
        });

        test('checks multiple stateful guards in order', function (): void {
            Config::set('bearer.guard', ['web', 'admin']);

            $user = createUser(['email' => uniqid().'@example.com']);

            $response = $this->actingAs($user, 'web')->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
            expect($response->json('token_type'))->toBe(TransientToken::class);
        });

        test('token with IP allowlist succeeds when IP matches', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'ip-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_ips' => ['127.0.0.1', '192.168.1.1'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
            ])->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('token with domain allowlist succeeds when Origin header matches', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'domain-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => ['example.com', 'api.example.com'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'Origin' => 'https://example.com',
            ])->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('token with domain allowlist succeeds when Referer header matches', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'referer-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => ['example.com'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'Referer' => 'https://example.com/page',
            ])->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });
    });

    describe('Sad Path', function (): void {
        test('returns 401 when no bearer token and no session', function (): void {
            $response = $this->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('returns 401 for non-existent token', function (): void {
            $response = $this->withHeader('Authorization', 'Bearer non-existent-token')->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('throws TokenRevokedException for revoked tokens', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'revoked-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'revoked_at' => now()->subHour(),
            ]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth'))
                ->toThrow(TokenRevokedException::class);
        });

        test('throws TokenExpiredException when token exceeds expiration minutes', function (): void {
            Config::set('bearer.expiration', 60);

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'expired-created-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'created_at' => now()->subMinutes(120),
            ]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth'))
                ->toThrow(TokenExpiredException::class);
        });

        test('throws TokenExpiredException when expires_at is in the past', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'expired-at-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'expires_at' => now()->subHour(),
            ]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth'))
                ->toThrow(TokenExpiredException::class);
        });

        test('returns 401 when IP not in allowlist', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'ip-restricted-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_ips' => ['192.168.1.1', '10.0.0.1'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
            ])->withServerVariables(['REMOTE_ADDR' => '8.8.8.8'])->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('returns 401 when domain not in allowlist', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'domain-restricted-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => ['example.com', 'trusted.com'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'Origin' => 'https://evil.com',
            ])->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('returns 401 when domain header is missing but domain restrictions exist', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'missing-domain-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => ['example.com'],
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->getJson('/test-auth');

            $response->assertUnauthorized();
        });
    });

    describe('Edge Cases', function (): void {
        test('returns user without token wrapper when session user lacks HasApiTokens trait', function (): void {
            $user = UserWithoutTokens::query()->create([
                'name' => 'No Token User',
                'email' => uniqid().'@example.com',
                'password' => bcrypt('password'),
            ]);

            // Create a custom route that doesn't call currentAccessToken()
            Route::middleware(['auth:bearer'])->get('/test-no-tokens', fn () => response()->json([
                'user_id' => Auth::id(),
                'user_class' => Auth::user() ? Auth::user()::class : null,
            ]));

            $response = $this->actingAs($user, 'web')->get('/test-no-tokens');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
            expect($response->json('user_class'))->toBe(UserWithoutTokens::class);
        });

        test('returns null when tokenable does not support tokens via bearer auth', function (): void {
            $user = UserWithoutTokens::query()->create([
                'name' => 'No Token User',
                'email' => uniqid().'@example.com',
                'password' => bcrypt('password'),
            ]);

            $plainToken = 'test-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'tokenable_type' => UserWithoutTokens::class,
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('returns 401 when domain header parse_url returns false', function (): void {
            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'invalid-domain-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => ['example.com'],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'Origin' => 'http:///invalid-url',
            ])->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('returns null when provider config model is not a string', function (): void {
            // Configure bearer guard with a provider
            Config::set('auth.guards.bearer.provider', 'users');
            Config::set('auth.providers.users.model', ['not' => 'string']); // Invalid - not a string

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'invalid-provider-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
            ]);

            // Recreate the auth guard to pick up new config
            app(Factory::class)->forgetGuards();

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->getJson('/test-auth');

            $response->assertUnauthorized();
        });

        test('empty IP allowlist array allows all IPs', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'empty-ip-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_ips' => [],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
            ])->withServerVariables(['REMOTE_ADDR' => '1.2.3.4'])->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('empty domain allowlist array allows all domains', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'empty-domain-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => [],
            ]);

            $response = $this->withHeaders([
                'Authorization' => 'Bearer '.$plainToken,
                'Origin' => 'https://any-domain.com',
            ])->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('token without expires_at does not expire', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'no-expiration-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'created_at' => now()->subYears(10),
                'expires_at' => null,
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('single guard string in config works correctly', function (): void {
            Config::set('bearer.guard', 'web');

            $user = createUser(['email' => uniqid().'@example.com']);

            $response = $this->actingAs($user, 'web')->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('prefers stateful guard over bearer token when both present', function (): void {
            $sessionUser = createUser(['email' => 'session-'.uniqid().'@example.com']);
            $tokenUser = createUser(['email' => 'token-'.uniqid().'@example.com']);

            $plainToken = 'both-present-token-'.uniqid();
            createRawToken($tokenUser, ['token' => hash('sha256', $plainToken)]);

            $response = $this->actingAs($sessionUser, 'web')
                ->withHeader('Authorization', 'Bearer '.$plainToken)
                ->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($sessionUser->id);
            expect($response->json('token_type'))->toBe(TransientToken::class);
        });

        test('null IP allowlist allows all IPs', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'null-ip-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_ips' => null,
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });

        test('null domain allowlist allows all domains', function (): void {
            Event::fake();

            $user = createUser(['email' => uniqid().'@example.com']);
            $plainToken = 'null-domain-token-'.uniqid();
            createRawToken($user, [
                'token' => hash('sha256', $plainToken),
                'allowed_domains' => null,
            ]);

            $response = $this->withHeader('Authorization', 'Bearer '.$plainToken)->get('/test-auth');

            $response->assertOk();

            expect($response->json('user_id'))->toBe($user->id);
        });
    });
});
