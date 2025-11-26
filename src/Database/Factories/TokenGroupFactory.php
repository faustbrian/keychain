<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Database\Factories;

use Cline\Keychain\Database\Models\TokenGroup;
use Illuminate\Database\Eloquent\Factories\Factory;
use Override;

/**
 * @extends Factory<TokenGroup>
 */
final class TokenGroupFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var class-string<TokenGroup>
     */
    protected $model = TokenGroup::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
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
