<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Http\Middleware\EnsureFrontendRequestsAreStateful;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;

describe('EnsureFrontendRequestsAreStateful', function (): void {
    beforeEach(function (): void {
        // Set up a test route with the middleware
        Route::middleware(EnsureFrontendRequestsAreStateful::class)->get('/test-stateful', fn (Request $request) => response()->json([
            'bearer' => $request->attributes->get('bearer'),
            'session_http_only' => config('session.http_only'),
            'session_same_site' => config('session.same_site'),
        ]));

        // Set app key for encryption
        Config::set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    });

    describe('Happy Path', function (): void {
        it('configures secure cookie sessions for all requests', function (): void {
            Config::set('bearer.stateful', []);

            $response = $this->get('/test-stateful');

            $response->assertOk();

            $data = $response->json();
            expect($data['session_http_only'])->toBeTrue();
            expect($data['session_same_site'])->toBe('lax');
        });

        it('marks request as from frontend when referer matches stateful domain', function (): void {
            Config::set('bearer.stateful', ['localhost']);

            $response = $this->withHeaders([
                'Referer' => 'http://localhost/app',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });

        it('marks request as from frontend when origin matches stateful domain', function (): void {
            Config::set('bearer.stateful', ['localhost']);

            $response = $this->withHeaders([
                'Origin' => 'http://localhost',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });

        it('does not mark request as from frontend when no matching domain', function (): void {
            Config::set('bearer.stateful', ['app.example.com']);

            $response = $this->withHeaders([
                'Referer' => 'http://external.com/page',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeNull();
        });

        it('applies frontend middleware stack for stateful requests', function (): void {
            Config::set('bearer.stateful', ['localhost']);

            $response = $this->withHeaders([
                'Referer' => 'http://localhost/app',
            ])->get('/test-stateful');

            $response->assertOk();
            // Request should be marked as from frontend
            expect($response->json('bearer'))->toBeTrue();
        });

        it('supports wildcard domain matching', function (): void {
            Config::set('bearer.stateful', ['*.example.com']);

            $response = $this->withHeaders([
                'Referer' => 'https://app.example.com/dashboard',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });

        it('supports current host placeholder', function (): void {
            Config::set('bearer.stateful', ['*']);

            $response = $this->withHeaders([
                'Referer' => 'http://localhost/app',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });
    });

    describe('Edge Cases', function (): void {
        it('handles request without referer or origin headers', function (): void {
            Config::set('bearer.stateful', ['localhost']);

            $response = $this->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeNull();
        });

        it('handles empty stateful domains config', function (): void {
            Config::set('bearer.stateful', []);

            $response = $this->withHeaders([
                'Referer' => 'http://localhost/app',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeNull();
        });

        it('normalizes https protocol in referer', function (): void {
            Config::set('bearer.stateful', ['secure.example.com']);

            $response = $this->withHeaders([
                'Referer' => 'https://secure.example.com/page',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });

        it('handles referer with port number', function (): void {
            Config::set('bearer.stateful', ['localhost:3000']);

            $response = $this->withHeaders([
                'Referer' => 'http://localhost:3000/app',
            ])->get('/test-stateful');

            $response->assertOk();

            expect($response->json('bearer'))->toBeTrue();
        });

        it('handles multiple stateful domains', function (): void {
            Config::set('bearer.stateful', ['localhost', 'app.example.com', '*.staging.com']);

            // Test first domain
            $response = $this->withHeaders([
                'Referer' => 'http://localhost/app',
            ])->get('/test-stateful');
            expect($response->json('bearer'))->toBeTrue();

            // Test second domain
            $response = $this->withHeaders([
                'Referer' => 'https://app.example.com/dashboard',
            ])->get('/test-stateful');
            expect($response->json('bearer'))->toBeTrue();

            // Test wildcard domain
            $response = $this->withHeaders([
                'Referer' => 'https://api.staging.com/test',
            ])->get('/test-stateful');
            expect($response->json('bearer'))->toBeTrue();
        });
    });
});
