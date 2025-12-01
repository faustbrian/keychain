<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Database\Factories;

use Cline\Bearer\Database\Models\AccessTokenAuditLog;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Database\Eloquent\Factories\Factory;
use Override;

/**
 * Factory for generating AccessTokenAuditLog model instances in tests and seeders.
 *
 * Creates realistic audit log entries with randomized event types, IP addresses,
 * and user agents for testing token activity tracking and security logging.
 *
 * @extends Factory<AccessTokenAuditLog>
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class AccessTokenAuditLogFactory extends Factory
{
    /**
     * The name of the factory's corresponding model.
     *
     * @var class-string<AccessTokenAuditLog>
     */
    protected $model = AccessTokenAuditLog::class;

    /**
     * Define the model's default state.
     *
     * Generates a token audit log entry with a random audit event type,
     * IPv4 address, and user agent string. The token_id must be set
     * when creating instances as it's a required foreign key.
     *
     * @return array<string, mixed> Model attribute defaults
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
