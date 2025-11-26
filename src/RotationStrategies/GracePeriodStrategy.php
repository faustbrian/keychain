<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\RotationStrategies;

use Cline\Keychain\Contracts\RotationStrategy;
use Cline\Keychain\Database\Models\PersonalAccessToken;

use function now;

/**
 * Grace period rotation strategy.
 *
 * Allows the old token to remain valid for a specified grace period after rotation,
 * giving clients time to transition to the new token without authentication failures.
 * This balances security with reliability by preventing immediate token invalidation.
 *
 * The grace period is implemented by setting the revoked_at timestamp to a future time.
 * During this period, both the old and new tokens are valid. After the grace period
 * expires, only the new token will authenticate successfully.
 *
 * This strategy is ideal for production environments where you need to ensure zero
 * downtime during token rotation. Clients can gradually transition to the new token
 * while still being able to fall back to the old one if needed.
 *
 * Use this strategy when:
 * - You need zero-downtime token rotation
 * - Clients may take time to process and store new tokens
 * - Network issues could prevent immediate token updates
 * - You want to balance security with reliability
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class GracePeriodStrategy implements RotationStrategy
{
    /**
     * Create a new grace period strategy instance.
     *
     * @param int $gracePeriodMinutes Duration in minutes for the grace period
     */
    public function __construct(
        private int $gracePeriodMinutes,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function rotate(PersonalAccessToken $oldToken, PersonalAccessToken $newToken): void
    {
        $oldToken->update(['revoked_at' => now()->addMinutes($this->gracePeriodMinutes)]);
    }

    /**
     * {@inheritDoc}
     */
    public function isOldTokenValid(PersonalAccessToken $oldToken): bool
    {
        return !$oldToken->revoked_at || $oldToken->revoked_at->isFuture();
    }

    /**
     * {@inheritDoc}
     */
    public function gracePeriodMinutes(): int
    {
        return $this->gracePeriodMinutes;
    }
}
