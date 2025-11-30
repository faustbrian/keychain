<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\TokenHashers;

use Cline\Bearer\Contracts\TokenHasher;

use function hash;
use function hash_equals;

/**
 * SHA-256 token hasher implementation.
 *
 * Uses SHA-256 hashing algorithm for token storage. This is the default
 * hasher providing a good balance of speed and security for API tokens.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Sha256TokenHasher implements TokenHasher
{
    /**
     * {@inheritDoc}
     */
    public function hash(string $token): string
    {
        return hash('sha256', $token);
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $token, string $hash): bool
    {
        return hash_equals($hash, $this->hash($token));
    }
}
