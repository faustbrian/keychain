<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Keychain\RevocationStrategies;

use Cline\Keychain\Contracts\RevocationStrategy;
use Cline\Keychain\Database\Models\PersonalAccessToken;
use Illuminate\Support\Collection;

use function collect;
use function now;

/**
 * Partial cascade revocation strategy.
 *
 * Revokes only specific token types within a token group, allowing other types
 * to remain valid. This enables selective invalidation patterns where certain
 * token types should be revoked together while others (like publishable keys)
 * should survive.
 *
 * By default, revokes 'sk' (secret) and 'rk' (restricted) tokens while leaving
 * 'pk' (publishable) tokens active. This is useful when you want to invalidate
 * server-side credentials without breaking client-side integrations.
 *
 * Use this strategy when:
 * - You need fine-grained control over group revocation
 * - Certain token types should survive security incidents
 * - Client-side tokens should remain valid when server keys rotate
 * - Different token types have different security requirements
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class PartialCascadeStrategy implements RevocationStrategy
{
    /**
     * Create a new partial cascade strategy instance.
     *
     * @param array<string> $prefixesToRevoke Token prefixes to revoke
     */
    public function __construct(
        private array $prefixesToRevoke,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function revoke(PersonalAccessToken $token): void
    {
        if ($token->group) {
            $token->group->tokens()
                ->whereIn('prefix', $this->prefixesToRevoke)
                ->update(['revoked_at' => now()]);
        } else {
            $token->update(['revoked_at' => now()]);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function getAffectedTokens(PersonalAccessToken $token): Collection
    {
        if ($token->group) {
            /** @var Collection<int, PersonalAccessToken> */
            return $token->group->tokens()
                ->whereIn('prefix', $this->prefixesToRevoke)
                ->get();
        }

        return collect([$token]);
    }
}
