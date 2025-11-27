<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\RevocationStrategies;

use Cline\Keychain\Contracts\RevocationStrategy;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Illuminate\Support\Collection;

use function collect;
use function now;

/**
 * Single token revocation strategy.
 *
 * Only revokes the specified token without affecting any related tokens.
 * This is the simplest and most conservative revocation strategy, providing
 * fine-grained control over token invalidation.
 *
 * Use this strategy when:
 * - You need precise control over which tokens are revoked
 * - Tokens are independent and not part of a group or hierarchy
 * - Users should be able to revoke individual sessions
 * - Security incidents are isolated to specific tokens
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class NoneStrategy implements RevocationStrategy
{
    /**
     * Revoke only the specified token.
     *
     * Performs a simple, isolated revocation of the given token without
     * affecting any related tokens, groups, or hierarchies. This is the
     * most conservative revocation approach.
     *
     * @param PersonalAccessToken $token The token to revoke
     */
    public function revoke(PersonalAccessToken $token): void
    {
        $token->update(['revoked_at' => now()]);
    }

    /**
     * Get all tokens that will be affected by revoking this token.
     *
     * Since this strategy only revokes the single token, this method returns
     * a collection containing only the given token. This provides consistency
     * with other revocation strategies' interfaces.
     *
     * @param  PersonalAccessToken                  $token The token to check
     * @return Collection<int, PersonalAccessToken> Collection containing only the given token
     */
    public function getAffectedTokens(PersonalAccessToken $token): Collection
    {
        return collect([$token]);
    }
}
