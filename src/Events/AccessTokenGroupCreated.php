<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Events;

use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\NewAccessToken;
use Illuminate\Support\Collection;

/**
 * Event fired when a token group is created.
 *
 * Dispatched whenever a new token group is created with its associated tokens.
 * Useful for auditing bulk token operations, tracking group-based token
 * management, and implementing organizational token hierarchies.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class AccessTokenGroupCreated
{
    /**
     * Create a new Token Group Created event.
     *
     * @param AccessTokenGroup                $group  The token group that was created
     * @param Collection<int, NewAccessToken> $tokens The collection of tokens in the group
     */
    public function __construct(
        public AccessTokenGroup $group,
        public Collection $tokens,
    ) {}
}
