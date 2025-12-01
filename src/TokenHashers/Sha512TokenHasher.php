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
 * SHA-512 token hasher implementation.
 *
 * Uses SHA-512 hashing algorithm for token storage. Provides stronger
 * security than SHA-256 at the cost of slightly longer hash values.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class Sha512TokenHasher implements TokenHasher
{
    /**
     * {@inheritDoc}
     */
    public function hash(string $token): string
    {
        return hash('sha512', $token);
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $token, string $hash): bool
    {
        return hash_equals($hash, $this->hash($token));
    }
}
