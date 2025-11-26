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
     * {@inheritDoc}
     */
    public function revoke(PersonalAccessToken $token): void
    {
        if ($token->group) {
            $token->group->tokens()->update(['revoked_at' => now()]);
        } else {
            $token->update(['revoked_at' => now()]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getAffectedTokens(PersonalAccessToken $token): Collection
    {
        if ($token->group === null) {
            return collect([$token]);
        }

        return $token->group->tokens;
    }
}
