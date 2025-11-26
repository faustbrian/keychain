<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Database\Factories;

use Cline\Keychain\Database\Models\TokenAuditLog;
use Cline\Keychain\Enums\AuditEvent;
use Illuminate\Database\Eloquent\Factories\Factory;
use Override;

/**
 * @extends Factory<TokenAuditLog>
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class TokenAuditLogFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var class-string<TokenAuditLog>
     */
    protected $model = TokenAuditLog::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    #[Override()]
    public function definition(): array
    {
        return [
            'event' => $this->faker->randomElement(AuditEvent::cases()),
            'ip_address' => $this->faker->ipv4(),
            'user_agent' => $this->faker->userAgent(),
            'metadata' => null,
        ];
    }
}
