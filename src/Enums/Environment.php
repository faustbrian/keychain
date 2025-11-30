<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Enums;

/**
 * Defines token environments for test/live separation.
 *
 * Similar to payment gateway environments (like Stripe's test/live modes),
 * this enum allows tokens to be scoped to specific environments, preventing
 * accidental use of test tokens in production or vice versa.
 *
 * @author Brian Faust <brian@cline.sh>
 */
enum Environment: string
{
    /**
     * Test environment for development and staging.
     *
     * Tokens in this environment are for testing purposes only and should
     * not be used in production contexts.
     */
    case Test = 'test';

    /**
     * Live environment for production use.
     *
     * Tokens in this environment are for production use and carry real
     * permissions and consequences.
     */
    case Live = 'live';

    /**
     * Returns the environment prefix for token identification.
     *
     * @return string The environment identifier ('test' or 'live')
     */
    public function prefix(): string
    {
        return $this->value;
    }
}
