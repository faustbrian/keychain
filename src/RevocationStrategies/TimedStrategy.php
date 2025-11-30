<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\RevocationStrategies;

use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Database\Models\AccessToken;
use Illuminate\Support\Collection;

use function collect;
use function now;

/**
 * Timed revocation strategy.
 *
 * Schedules token revocation for a future time instead of revoking immediately.
 * This allows for delayed invalidation, giving users or systems time to transition
 * away from a token before it becomes invalid.
 *
 * The token will remain valid until the scheduled revocation time, after which
 * it will be treated as revoked. This is useful for planned maintenance windows,
 * gradual rollouts of new credentials, or giving advance notice of revocation.
 *
 * Use this strategy when:
 * - You need to give advance notice before revoking tokens
 * - Scheduled maintenance requires token invalidation
 * - Users need time to transition to new credentials
 * - You want to coordinate revocation with other system changes
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TimedStrategy implements RevocationStrategy
{
    /**
     * Create a new timed strategy instance.
     *
     * @param int $delayMinutes Number of minutes to delay the revocation. The token
     *                          will remain valid for this duration before becoming
     *                          revoked. Defaults to 60 minutes if not specified in
     *                          configuration.
     */
    public function __construct(
        private int $delayMinutes,
    ) {}

    /**
     * Schedule the token for future revocation.
     *
     * Sets the token's revocation timestamp to a future time instead of
     * immediately revoking it. The token will remain valid until the scheduled
     * revocation time arrives. This enables grace periods for credential rotation
     * or planned maintenance windows.
     *
     * @param AccessToken $token The token to schedule for revocation
     */
    public function revoke(AccessToken $token): void
    {
        $token->update(['revoked_at' => now()->addMinutes($this->delayMinutes)]);
    }

    /**
     * Get all tokens that will be affected by revoking this token.
     *
     * Since this strategy only affects the single token (albeit on a delayed
     * schedule), this method returns a collection containing only the given token.
     * This provides consistency with other revocation strategies' interfaces.
     *
     * @param  AccessToken                  $token The token to check
     * @return Collection<int, AccessToken> Collection containing only the given token
     */
    public function getAffectedTokens(AccessToken $token): Collection
    {
        return collect([$token]);
    }
}
