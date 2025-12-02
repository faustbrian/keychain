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
 * Immediate invalidation rotation strategy.
 *
 * Immediately revokes the old token when rotation occurs, making it invalid
 * for any further use. This is the most secure rotation strategy but requires
 * clients to transition to the new token atomically.
 *
 * The old token is marked as revoked the moment the new token is created,
 * ensuring that only one token is ever valid at any given time. This prevents
 * token reuse but may cause issues if the client fails to receive or store
 * the new token.
 *
 * Use this strategy when:
 * - Security is paramount and token reuse must be prevented
 * - Clients can reliably receive and store new tokens
 * - You're willing to handle failed rotations (client didn't get new token)
 * - The system can tolerate brief authentication failures during rotation
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class ImmediateInvalidationStrategy implements RotationStrategy
{
    /**
     * Rotate the token and immediately revoke the old token.
     *
     * Marks the old token as revoked the moment rotation occurs by setting
     * revoked_at to the current timestamp. This ensures only one token is
     * valid at any time, providing maximum security at the cost of requiring
     * atomic token updates by clients.
     *
     * @param AccessToken $oldToken The existing token being rotated and revoked
     * @param AccessToken $newToken The newly generated replacement token
     */
    public function rotate(AccessToken $oldToken, AccessToken $newToken): void
    {
        $oldToken->update(['revoked_at' => now()]);
    }

    /**
     * Check if the old token is still valid after rotation.
     *
     * Always returns false as this strategy immediately invalidates old tokens
     * upon rotation, ensuring only the new token can be used for authentication.
     *
     * @param  AccessToken $oldToken The old token to validate
     * @return bool        Always returns false for this strategy
     */
    public function isOldTokenValid(AccessToken $oldToken): bool
    {
        return false;
    }

    /**
     * Get the grace period duration in minutes.
     *
     * Returns null as this strategy does not use a grace period. Old tokens
     * are immediately invalidated with no transition period.
     */
    public function gracePeriodMinutes(): ?int
    {
        return null;
    }
}
