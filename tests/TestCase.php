<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests;

use Cline\Ancestry\AncestryServiceProvider;
use Cline\Bearer\BearerServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\TestCase as Orchestra;
use Override;

/**
 * Base test case for Bearer package tests.
 *
 * Provides test infrastructure including:
 * - Orchestra Testbench setup for package testing
 * - RefreshDatabase trait for clean database state per test
 * - Automatic loading of package migrations
 * - SQLite in-memory database configuration
 * - Bearer service provider registration
 * - Package configuration defaults
 *
 * @internal
 *
 * @author Brian Faust <brian@cline.sh>
 */
abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    /**
     * Set up the test environment.
     *
     * Loads migrations from both the package and test fixtures.
     */
    #[Override()]
    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/Fixtures/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../vendor/cline/ancestry/database/migrations');
    }

    /**
     * Get package providers.
     *
     * @param  Application              $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            BearerServiceProvider::class,
            AncestryServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * Configures the test environment with:
     * - SQLite in-memory database for speed and isolation
     * - Bearer default configuration for testing
     *
     * @param Application $app
     */
    protected function defineEnvironment($app): void
    {
        $app->make(Repository::class)->set('database.default', 'testing');
        $app->make(Repository::class)->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Load bearer configuration
        $config = require __DIR__.'/../config/bearer.php';
        $app->make(Repository::class)->set('bearer', $config);
    }

    /**
     * Get the base path for the package.
     */
    protected function getBasePath(): string
    {
        return __DIR__.'/../';
    }
}
