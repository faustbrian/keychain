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
 * Event fired when a token is used for authentication.
 *
 * Dispatched whenever a personal access token is successfully authenticated.
 * Useful for auditing token usage, tracking authentication patterns, and
 * implementing security monitoring.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenAuthenticated
{
    /**
     * Create a new Token Authenticated event.
     *
     * @param AccessToken $token     The token that was authenticated
     * @param null|string $ipAddress The IP address from which the token was used
     * @param null|string $userAgent The user agent that used the token
     */
    public function __construct(
        public AccessToken $token,
        public ?string $ipAddress = null,
        public ?string $userAgent = null,
    ) {}
}
