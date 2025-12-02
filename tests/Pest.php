<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Facades\Bearer;
use Tests\Fixtures\User;
use Tests\TestCase;

pest()->extend(TestCase::class)->in(__DIR__);

/**
 * Create a test user with default or custom attributes.
 *
 * Provides a convenient way to create User instances for testing with sensible
 * defaults. All attributes can be overridden via the $attributes parameter.
 *
 * @param  array<string, mixed> $attributes Custom attributes to merge with defaults
 * @return User                 The created user instance
 */
function createUser(array $attributes = []): User
{
    return User::query()->create(array_merge([
        'name' => 'Test User',
        'email' => 'test@example.com',
        'password' => bcrypt('password'),
    ], $attributes));
}

/**
 * Create a personal access token for a user.
 *
 * Issues a token using the Bearer service for the specified user. Supports
 * customization of token type, name, abilities, and environment.
 *
 * @param  User                 $user       The user to create the token for
 * @param  string               $type       The token type (default: 'sk' for secret key)
 * @param  array<string, mixed> $attributes Custom token attributes (name, abilities, environment)
 * @return AccessToken          The created token model instance
 */
function createAccessToken(User $user, string $type = 'sk', array $attributes = []): AccessToken
{
    $newToken = Bearer::for($user)->issue(
        type: $type,
        name: $attributes['name'] ?? 'Test Token',
        abilities: $attributes['abilities'] ?? ['*'],
        environment: $attributes['environment'] ?? 'test',
    );

    return $newToken->accessToken;
}
