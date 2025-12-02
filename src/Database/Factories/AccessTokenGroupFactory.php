<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Database\Factories;

use Cline\Bearer\Database\Models\AccessTokenGroup;
use Illuminate\Database\Eloquent\Factories\Factory;
use Override;

/**
 * Factory for generating AccessTokenGroup model instances in tests and seeders.
 *
 * Creates token groups with randomized names for testing grouped token
 * management, batch operations, and sibling token relationships.
 *
 * @extends Factory<AccessTokenGroup>
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AccessTokenGroupFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var class-string<AccessTokenGroup>
     */
    protected $model = AccessTokenGroup::class;

    /**
     * Define the model's default state.
     *
     * Generates a token group with a random three-word name. The owner
     * relationship (owner_id and owner_type) should be set when creating
     * instances to link the group to a tokenable model.
     *
     * @return array<string, mixed> Model attribute defaults
     */
    #[Override()]
    public function definition(): array
    {
        return [
            'name' => $this->faker->words(3, true),
            'metadata' => null,
        ];
    }
}
