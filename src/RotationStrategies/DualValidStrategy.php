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
     * {@inheritDoc}
     */
    public function rotate(PersonalAccessToken $oldToken, PersonalAccessToken $newToken): void
    {
        // Don't revoke old token - both remain valid
        // Optionally, you could link them via metadata for audit purposes
    }

    /**
     * {@inheritDoc}
     */
    public function isOldTokenValid(PersonalAccessToken $oldToken): bool
    {
        return !$oldToken->isRevoked();
    }

    /**
     * {@inheritDoc}
     */
    public function gracePeriodMinutes(): ?int
    {
        return null; // Indefinite - no grace period concept
    }
}
