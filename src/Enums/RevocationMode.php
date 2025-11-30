<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Enums;

/**
 * Defines revocation cascade modes for token invalidation.
 *
 * This enum determines the scope of token revocation, allowing fine-grained
 * control over which tokens should be invalidated when a revocation is triggered.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum RevocationMode: string
{
    /**
     * Revoke only the specified token.
     *
     * Only the explicitly targeted token will be invalidated. No other
     * tokens in the same group or related tokens will be affected.
     */
    case None = 'none';

    /**
     * Revoke entire token group.
     *
     * All tokens belonging to the same group will be invalidated. Useful
     * for revoking all tokens associated with a session or user account.
     */
    case Cascade = 'cascade';

    /**
     * Revoke specific token types in group.
     *
     * Only tokens of specific types within the group will be invalidated.
     * Allows selective revocation while preserving other token types.
     */
    case Partial = 'partial';

    /**
     * Schedule revocation for later.
     *
     * Token revocation will be scheduled to occur at a future time, allowing
     * for grace periods or coordinated invalidation across systems.
     */
    case Timed = 'timed';
}
