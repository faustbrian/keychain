<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Fixtures;

use Cline\Bearer\Concerns\HasApiTokens;
use Cline\Bearer\Contracts\HasApiTokens as HasApiTokensContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;

/**
 * Test fixture user model.
 *
 * Provides a minimal User implementation for testing the Bearer package.
 * Uses the HasApiTokens trait to enable token-based authentication functionality.
 *
 * This fixture model is used throughout the test suite to simulate real-world
 * usage of the package with a typical Eloquent user model.
 *
 * @internal
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class User extends Authenticatable implements HasApiTokensContract
{
    use HasFactory;
    use HasApiTokens;

    /**
     * The attributes that aren't mass assignable.
     *
     * @var array<string>
     */
    protected $guarded = [];

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'users';
}
