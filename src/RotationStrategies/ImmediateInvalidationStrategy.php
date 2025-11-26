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
     * {@inheritDoc}
     */
    public function rotate(PersonalAccessToken $oldToken, PersonalAccessToken $newToken): void
    {
        $oldToken->update(['revoked_at' => now()]);
    }

    /**
     * {@inheritDoc}
     */
    public function isOldTokenValid(PersonalAccessToken $oldToken): bool
    {
        return false;
    }

    /**
     * {@inheritDoc}
     */
    public function gracePeriodMinutes(): ?int
    {
        return null;
    }
}
