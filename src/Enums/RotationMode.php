<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Enums;

/**
 * Defines rotation invalidation modes for token replacement.
 *
 * This enum controls how old tokens are handled when a token is rotated
 * (replaced with a new one), balancing security with operational flexibility.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum RotationMode: string
{
    /**
     * Old token is invalid immediately.
     *
     * The previous token becomes invalid as soon as the new token is created.
     * Provides maximum security but requires immediate client updates.
     */
    case Immediate = 'immediate';

    /**
     * Old token valid for grace period.
     *
     * The previous token remains valid for a configured time period after
     * rotation. Allows for gradual migration and prevents disruption during
     * deployments or updates.
     */
    case GracePeriod = 'grace';

    /**
     * Both tokens valid until explicit revoke.
     *
     * Both the old and new tokens remain valid until one is explicitly
     * revoked. Provides maximum flexibility but requires manual cleanup.
     */
    case DualValid = 'dual';
}
