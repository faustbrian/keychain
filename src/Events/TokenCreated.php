<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Events;

use Cline\Bearer\Database\Models\AccessToken;

/**
 * Event fired when a new token is created.
 *
 * Dispatched whenever a new personal access token is created in the system.
 * Useful for auditing token creation, triggering notifications, and tracking
 * token issuance patterns across different types and environments.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenCreated
{
    /**
     * Create a new Token Created event.
     *
     * @param AccessToken $token       The newly created token
     * @param string      $tokenType   The type of token that was created
     * @param string      $environment The environment in which the token was created
     */
    public function __construct(
        public AccessToken $token,
        public string $tokenType,
        public string $environment,
    ) {}
}
