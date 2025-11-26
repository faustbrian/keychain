<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\Events;

use Cline\Keychain\Database\Models\PersonalAccessToken;
use Cline\Keychain\Enums\RotationMode;

/**
 * Event fired when a token is rotated.
 *
 * Dispatched whenever a personal access token is rotated to a new token.
 * Useful for auditing token rotation, tracking security best practices,
 * and implementing lifecycle management for tokens.
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenRotated
{
    /**
     * Create a new Token Rotated event.
     *
     * @param PersonalAccessToken $oldToken The token that was rotated out
     * @param PersonalAccessToken $newToken The new token that replaced it
     * @param RotationMode        $mode     The mode used for rotation
     */
    public function __construct(
        public PersonalAccessToken $oldToken,
        public PersonalAccessToken $newToken,
        public RotationMode $mode,
    ) {}
}
