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

/**
 * Dual valid rotation strategy.
 *
 * Keeps both the old and new tokens valid indefinitely until one is explicitly
 * revoked. This provides maximum flexibility but reduces security by allowing
 * multiple valid tokens to exist simultaneously.
 *
 * Neither token is automatically revoked during rotation. The old token remains
 * fully functional alongside the new token until manually revoked. This strategy
 * is useful when you want to maintain backward compatibility or when clients may
 * need to use either token interchangeably.
 *
 * Note: This strategy does not automatically revoke old tokens, so you should
 * implement manual cleanup or periodic revocation of old tokens to prevent
 * unlimited token accumulation.
 *
 * Use this strategy when:
 * - Maximum flexibility is required over security
 * - Clients need to use either old or new tokens interchangeably
 * - You have manual token management processes in place
 * - Backward compatibility is critical
 * - You're implementing a migration period for token formats
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class DualValidStrategy implements RotationStrategy
{
    /**
     * Rotate the token while keeping both old and new tokens valid.
     *
     * This method does not revoke the old token, allowing both tokens to remain
     * valid indefinitely until explicitly revoked. This provides maximum flexibility
     * but requires manual token management to prevent unlimited token accumulation.
     *
     * @param AccessToken $oldToken The existing token being rotated
     * @param AccessToken $newToken The newly generated replacement token
     */
    public function rotate(AccessToken $oldToken, AccessToken $newToken): void
    {
        // Don't revoke old token - both remain valid
        // Optionally, you could link them via metadata for audit purposes
    }

    /**
     * Check if the old token is still valid after rotation.
     *
     * Returns true as long as the old token has not been explicitly revoked,
     * allowing it to remain valid indefinitely alongside the new token.
     *
     * @param  AccessToken $oldToken The old token to validate
     * @return bool        True if the token is not revoked, false otherwise
     */
    public function isOldTokenValid(AccessToken $oldToken): bool
    {
        return !$oldToken->isRevoked();
    }

    /**
     * Get the grace period duration in minutes.
     *
     * Returns null as this strategy does not use a grace period concept.
     * Both tokens remain valid indefinitely without any time-based constraints.
     */
    public function gracePeriodMinutes(): ?int
    {
        return null; // Indefinite - no grace period concept
    }
}
