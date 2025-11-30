<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

use Cline\Bearer\Database\Models\AccessToken;
use Illuminate\Support\Collection;

/**
 * Contract for token revocation strategies.
 *
 * Revocation strategies define how tokens are invalidated and what cascade
 * effects occur when a token is revoked. Different strategies enable various
 * security models and use cases, from simple single-token revocation to
 * complex hierarchical invalidation.
 *
 * Common revocation scenarios:
 * - Single token: Revoke only the specific token
 * - Token family: Revoke all tokens in a rotation chain
 * - Token group: Revoke all tokens in a logical group
 * - User tokens: Revoke all tokens for a user
 * - Cascade revocation: Revoke tokens that depend on this token
 *
 * Strategies are particularly important for:
 * - Security incidents requiring broad token invalidation
 * - User logout functionality (revoke current vs all tokens)
 * - Token rotation chains where old tokens must be invalidated
 * - Hierarchical token systems with parent-child relationships
 *
 * ```php
 * class SingleTokenRevocation implements RevocationStrategy
 * {
 *     public function revoke(AccessToken $token): void
 *     {
 *         $token->update(['revoked_at' => now()]);
 *     }
 *
 *     public function getAffectedTokens(AccessToken $token): Collection
 *     {
 *         return collect([$token]);
 *     }
 * }
 *
 * class TokenFamilyRevocation implements RevocationStrategy
 * {
 *     public function revoke(AccessToken $token): void
 *     {
 *         // Revoke all tokens in the same rotation chain
 *         AccessToken::where('rotation_chain_id', $token->rotation_chain_id)
 *             ->update(['revoked_at' => now()]);
 *     }
 *
 *     public function getAffectedTokens(AccessToken $token): Collection
 *     {
 *         return AccessToken::where('rotation_chain_id', $token->rotation_chain_id)->get();
 *     }
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface RevocationStrategy
{
    /**
     * Revoke a token according to this strategy.
     *
     * Performs the revocation operation, which may affect just the given token
     * or cascade to related tokens depending on the strategy implementation.
     * After revocation, affected tokens should fail authentication attempts.
     *
     * Implementations should:
     * - Mark tokens as revoked (timestamp or boolean flag)
     * - Trigger any necessary cascade operations
     * - Emit audit events for revoked tokens
     * - Handle edge cases (already revoked, expired, etc.)
     * - Be idempotent (safe to call multiple times)
     *
     * The method should not throw exceptions for tokens that are already
     * revoked or otherwise invalid; it should handle such cases gracefully.
     *
     * @param AccessToken $token The token to revoke (may trigger cascade)
     */
    public function revoke(AccessToken $token): void;

    /**
     * Get all tokens that will be affected by revoking the given token.
     *
     * Returns a collection of all tokens that would be invalidated if the
     * revoke() method were called on the given token. This enables:
     * - Previewing revocation impact before executing
     * - Warning users about how many tokens will be affected
     * - Audit logging of all affected tokens
     * - UI display of revocation scope
     *
     * For single-token strategies, this returns a collection containing only
     * the given token. For cascade strategies, it may return dozens or hundreds
     * of tokens depending on the relationships.
     *
     * @param  AccessToken                  $token The token to check revocation impact for
     * @return Collection<int, AccessToken> All tokens that would be revoked
     */
    public function getAffectedTokens(AccessToken $token): Collection;
}
