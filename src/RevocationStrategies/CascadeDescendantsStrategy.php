<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\RevocationStrategies;

use Cline\Ancestry\Facades\Ancestry;
use Cline\Bearer\Contracts\RevocationStrategy;
use Cline\Bearer\Database\Models\AccessToken;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Config;

use function assert;
use function collect;
use function is_string;
use function now;

/**
 * Cascade descendants revocation strategy for hierarchical tokens.
 *
 * Revokes the specified token and all of its descendant tokens in the
 * derivation hierarchy. This ensures that when a parent token is revoked,
 * all derived child tokens are automatically invalidated as well.
 *
 * Use this strategy when:
 * - Tokens are organized in a hierarchical derivation structure
 * - You want to revoke a master token and all derived customer tokens
 * - Security incidents affect a parent token and all its derivatives
 * - Resellers need to invalidate all customer tokens at once
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class CascadeDescendantsStrategy implements RevocationStrategy
{
    /**
     * Revoke the token and all its descendants in the hierarchy.
     *
     * Uses the configured hierarchy type to traverse the token derivation tree
     * and revoke all descendant tokens before revoking the parent token itself.
     * This ensures complete invalidation of an entire token ancestry.
     *
     * @param AccessToken $token The token to revoke along with its descendants
     */
    public function revoke(AccessToken $token): void
    {
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');
        assert(is_string($hierarchyType));

        // Get all descendants
        $descendants = Ancestry::getDescendants($token, $hierarchyType, includeSelf: false);

        // Revoke all descendants
        foreach ($descendants as $descendant) {
            $descendant->update(['revoked_at' => now()]);
        }

        // Revoke self
        $token->update(['revoked_at' => now()]);
    }

    /**
     * Get all tokens that will be affected by revoking this token.
     *
     * Returns the token itself plus all of its descendants in the derivation
     * hierarchy. This provides visibility into the scope of a revocation
     * operation before it is executed.
     *
     * @param  AccessToken                  $token The token to check
     * @return Collection<int, AccessToken> Collection containing the token and all descendants
     */
    public function getAffectedTokens(AccessToken $token): Collection
    {
        $hierarchyType = Config::get('bearer.derivation.hierarchy_type', 'token_derivation');
        assert(is_string($hierarchyType));

        // Get all descendants plus the token itself
        $descendants = Ancestry::getDescendants($token, $hierarchyType, includeSelf: true);

        /** @var Collection<int, AccessToken> */
        return collect($descendants->all());
    }
}
