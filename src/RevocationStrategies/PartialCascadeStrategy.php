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
 * Partial cascade revocation strategy.
 *
 * Revokes only specific token types within a token group, allowing other types
 * to remain valid. This enables selective invalidation patterns where certain
 * token types should be revoked together while others (like publishable keys)
 * should survive.
 *
 * By default, revokes 'sk' (secret) and 'rk' (restricted) tokens while leaving
 * 'pk' (publishable) tokens active. This is useful when you want to invalidate
 * server-side credentials without breaking client-side integrations.
 *
 * Use this strategy when:
 * - You need fine-grained control over group revocation
 * - Certain token types should survive security incidents
 * - Client-side tokens should remain valid when server keys rotate
 * - Different token types have different security requirements
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class PartialCascadeStrategy implements RevocationStrategy
{
    /**
     * Create a new partial cascade strategy instance.
     *
     * @param array<int, string> $prefixesToRevoke Token type prefixes that should be revoked when
     *                                             this strategy is applied. Typically includes
     *                                             sensitive token types like 'sk' and 'rk' while
     *                                             excluding safe types like 'pk'.
     */
    public function __construct(
        private array $prefixesToRevoke,
    ) {}

    /**
     * Revoke only specific token types within a group.
     *
     * If the token belongs to a group, revokes only tokens in that group whose
     * prefixes match the configured list. If the token is standalone, revokes
     * only the token itself. This enables selective invalidation where some
     * token types survive while others are revoked.
     *
     * @param AccessToken $token The token to revoke
     */
    public function revoke(AccessToken $token): void
    {
        if ($token->group) {
            $token->group->tokens()
                ->whereIn('prefix', $this->prefixesToRevoke)
                ->update(['revoked_at' => now()]);
        } else {
            $token->update(['revoked_at' => now()]);
        }
    }

    /**
     * Get all tokens that will be affected by revoking this token.
     *
     * Returns all tokens in the same group whose prefixes match the configured
     * list. If the token is not part of a group, returns only the token itself.
     * This provides visibility into which tokens will be revoked based on their
     * type prefix.
     *
     * @param  AccessToken                  $token The token to check
     * @return Collection<int, AccessToken> Collection of affected tokens
     */
    public function getAffectedTokens(AccessToken $token): Collection
    {
        if ($token->group) {
            /** @var Collection<int, AccessToken> */
            return $token->group->tokens()
                ->whereIn('prefix', $this->prefixesToRevoke)
                ->get();
        }

        return collect([$token]);
    }
}
