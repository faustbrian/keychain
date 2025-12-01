<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Contracts;

use Cline\Bearer\Database\Models\AccessToken;

/**
 * Contract for token rotation strategies.
 *
 * Rotation strategies define how tokens are refreshed/renewed and what happens
 * to old tokens during the rotation process. This enables sophisticated token
 * lifecycle management that balances security (frequent rotation) with usability
 * (grace periods for clients to transition).
 *
 * Token rotation is critical for:
 * - Reducing the impact of token theft (short-lived credentials)
 * - Maintaining long-running sessions without static tokens
 * - Implementing zero-downtime token transitions
 * - Meeting compliance requirements for credential rotation
 *
 * Common rotation patterns:
 * - Immediate invalidation: Old token stops working instantly
 * - Grace period: Old token valid for N minutes after rotation
 * - One-time use: Old token can only be used once more
 * - Parallel validity: Both tokens work until old expires
 *
 * ```php
 * class GracePeriodRotation implements RotationStrategy
 * {
 *     public function __construct(private int $gracePeriodMinutes = 5) {}
 *
 *     public function rotate(AccessToken $oldToken, AccessToken $newToken): void
 *     {
 *         $newToken->rotation_chain_id = $oldToken->rotation_chain_id ?? $oldToken->id;
 *         $newToken->replaces_token_id = $oldToken->id;
 *         $newToken->save();
 *
 *         $oldToken->rotated_at = now();
 *         $oldToken->rotation_grace_until = now()->addMinutes($this->gracePeriodMinutes);
 *         $oldToken->save();
 *     }
 *
 *     public function isOldTokenValid(AccessToken $oldToken): bool
 *     {
 *         if (!$oldToken->rotated_at) {
 *             return true; // Never rotated
 *         }
 *
 *         return now()->isBefore($oldToken->rotation_grace_until);
 *     }
 *
 *     public function gracePeriodMinutes(): ?int
 *     {
 *         return $this->gracePeriodMinutes;
 *     }
 * }
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 */
interface RotationStrategy
{
    /**
     * Perform the rotation from an old token to a new token.
     *
     * Implements the rotation logic, establishing the relationship between
     * old and new tokens and setting appropriate validity periods. This method
     * is called after the new token has been created but before it's returned
     * to the client.
     *
     * Implementations should:
     * - Link new token to old token (for audit trail and rotation chains)
     * - Mark old token as rotated with appropriate timestamp
     * - Set grace period expiration if applicable
     * - Maintain rotation chain IDs for tracking token families
     * - Copy relevant metadata (abilities, restrictions) if needed
     * - Emit rotation audit events
     *
     * The method should handle the complete state transition, leaving both
     * tokens in a consistent state that isOldTokenValid() can evaluate.
     *
     * @param AccessToken $oldToken The token being rotated/replaced
     * @param AccessToken $newToken The newly created replacement token
     */
    public function rotate(AccessToken $oldToken, AccessToken $newToken): void;

    /**
     * Determine if an old token is still valid after rotation.
     *
     * Evaluates whether a token that has been rotated should still be accepted
     * for authentication. This enables grace periods and other rotation patterns
     * that don't immediately invalidate old tokens.
     *
     * Called during authentication to determine if rotated tokens can still be
     * used. Implementations should consider:
     * - Whether the token has been rotated (rotated_at timestamp)
     * - Grace period expiration
     * - Number of uses since rotation (for one-time-use patterns)
     * - Explicit revocation status
     *
     * Returns true if the old token should still authenticate successfully,
     * false if it should be rejected. Never-rotated tokens should return true.
     *
     * @param  AccessToken $oldToken The rotated token to check validity for
     * @return bool        True if the old token can still be used, false if it should be rejected
     */
    public function isOldTokenValid(AccessToken $oldToken): bool;

    /**
     * Get the grace period duration in minutes.
     *
     * Returns the number of minutes old tokens remain valid after rotation,
     * or null if there's no grace period (immediate invalidation) or if the
     * strategy uses a different validity mechanism (like one-time use).
     *
     * This information is useful for:
     * - Documenting the rotation behavior
     * - Warning users about how long they have to transition
     * - Calculating when old tokens will expire
     * - UI display of rotation timelines
     *
     * @return null|int Grace period in minutes, or null if not applicable
     */
    public function gracePeriodMinutes(): ?int;
}
