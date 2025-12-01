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
 * Cascade revocation strategy for token groups.
 *
 * Revokes all tokens in the same token group as the specified token.
 * If the token is not part of a group, only the token itself is revoked.
 * This strategy is useful for invalidating all tokens associated with a
 * specific logical grouping (e.g., all tokens for a specific device or session).
 *
 * Use this strategy when:
 * - Tokens are organized into logical groups
 * - You want to revoke all related tokens together
 * - Security incidents affect an entire group
 * - Users want to logout from all devices in a group
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CascadeStrategy implements RevocationStrategy
{
    /**
     * Revoke the token and all tokens in its group.
     *
     * If the token belongs to a group, revokes all tokens in that group.
     * If the token is standalone (not part of a group), only revokes the
     * token itself. This enables group-level invalidation for related tokens.
     *
     * @param AccessToken $token The token to revoke
     */
    public function revoke(AccessToken $token): void
    {
        if ($token->group) {
            $token->group->accessTokens()->update(['revoked_at' => now()]);
        } else {
            $token->update(['revoked_at' => now()]);
        }
    }

    /**
     * Get all tokens that will be affected by revoking this token.
     *
     * Returns all tokens in the same group as the given token. If the token
     * is not part of a group, returns only the token itself. This provides
     * visibility into the scope of a revocation operation before execution.
     *
     * @param  AccessToken                  $token The token to check
     * @return Collection<int, AccessToken> Collection of affected tokens
     */
    public function getAffectedTokens(AccessToken $token): Collection
    {
        if ($token->group === null) {
            return collect([$token]);
        }

        return $token->group->accessTokens;
    }
}
