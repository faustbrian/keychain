<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\RotationStrategies;

use Cline\Bearer\Contracts\RotationStrategy;
use Cline\Bearer\Database\Models\AccessToken;

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
     * @param int $gracePeriodMinutes Duration in minutes that the old token remains valid
     *                                after rotation. This allows clients time to transition
     *                                to the new token without authentication failures.
     */
    public function __construct(
        private int $gracePeriodMinutes,
    ) {}

    /**
     * Rotate the token and schedule the old token for revocation after the grace period.
     *
     * Sets the old token's revoked_at timestamp to a future time based on the configured
     * grace period. During this period, both old and new tokens remain valid, allowing
     * clients to gracefully transition without downtime.
     *
     * @param AccessToken $oldToken The existing token being rotated
     * @param AccessToken $newToken The newly generated replacement token
     */
    public function rotate(AccessToken $oldToken, AccessToken $newToken): void
    {
        $oldToken->update(['revoked_at' => now()->addMinutes($this->gracePeriodMinutes)]);
    }

    /**
     * Check if the old token is still within its grace period.
     *
     * Returns true if the token has not been revoked or if the revocation timestamp
     * is in the future (within the grace period). Once the grace period expires,
     * this method returns false and the token becomes invalid.
     *
     * @param  AccessToken $oldToken The old token to validate
     * @return bool        True if the token is not revoked or revocation is in the future
     */
    public function isOldTokenValid(AccessToken $oldToken): bool
    {
        return !$oldToken->revoked_at || $oldToken->revoked_at->isFuture();
    }

    /**
     * Get the configured grace period duration in minutes.
     *
     * @return int The number of minutes old tokens remain valid after rotation
     */
    public function gracePeriodMinutes(): int
    {
        return $this->gracePeriodMinutes;
    }
}
