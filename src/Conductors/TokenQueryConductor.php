<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Conductors;

use Cline\Bearer\Contracts\HasApiTokens as HasApiTokensContract;
use Cline\Bearer\Database\Models\AccessToken;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;

use function now;

/**
 * Fluent conductor for querying tokens with chainable filters.
 *
 * Provides a builder pattern for constructing complex token queries with
 * chainable filter methods. Supports filtering by type, environment, validity
 * status, expiration, and revocation status.
 *
 * Example usage:
 * ```php
 * // Get all valid production secret keys
 * $tokens = Bearer::for($user)
 *     ->query()
 *     ->type('secret_key')
 *     ->environment('production')
 *     ->valid()
 *     ->get();
 *
 * // Count expired tokens
 * $count = Bearer::for($user)
 *     ->query()
 *     ->expired()
 *     ->count();
 *
 * // Get first revoked token
 * $token = Bearer::for($user)
 *     ->query()
 *     ->revoked()
 *     ->first();
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class TokenQueryConductor
{
    /**
     * The query builder instance.
     *
     * @var Builder<AccessToken>
     */
    private Builder $query;

    /**
     * Create a new token query conductor instance.
     *
     * @param HasApiTokensContract&Model $tokenable Eloquent model that owns the tokens to be queried.
     *                                              Typically a User model with HasApiTokens trait.
     *                                              The conductor builds queries against this model's
     *                                              tokens relationship for filtering and retrieval.
     */
    public function __construct(
        private Model&HasApiTokensContract $tokenable,
    ) {
        /** @var Builder<AccessToken> $query */
        $query = $this->tokenable->tokens()->getQuery();
        $this->query = $query;
    }

    /**
     * Filter tokens by type.
     *
     * @param  string $type Token type to filter by (e.g., 'secret_key', 'publishable_key')
     * @return self   Current conductor instance for method chaining
     */
    public function type(string $type): self
    {
        $this->query->where('type', $type);

        return $this;
    }

    /**
     * Filter tokens by environment.
     *
     * @param  string $environment Environment to filter by (e.g., 'production', 'development')
     * @return self   Current conductor instance for method chaining
     */
    public function environment(string $environment): self
    {
        $this->query->where('environment', $environment);

        return $this;
    }

    /**
     * Filter to only valid tokens.
     *
     * Valid tokens are those that are not expired and not revoked.
     *
     * @return self Current conductor instance for method chaining
     */
    public function valid(): self
    {
        $this->query
            ->whereNull('revoked_at')
            ->where(function (Builder $query): void {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });

        return $this;
    }

    /**
     * Filter to only expired tokens.
     *
     * @return self Current conductor instance for method chaining
     */
    public function expired(): self
    {
        $this->query
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());

        return $this;
    }

    /**
     * Filter to only revoked tokens.
     *
     * @return self Current conductor instance for method chaining
     */
    public function revoked(): self
    {
        $this->query->whereNotNull('revoked_at');

        return $this;
    }

    /**
     * Filter tokens by group.
     *
     * @param  int|string $groupId Token group ID
     * @return self       Current conductor instance for method chaining
     */
    public function group(int|string $groupId): self
    {
        $this->query->where('group_id', $groupId);

        return $this;
    }

    /**
     * Filter to only tokens without a group.
     *
     * @return self Current conductor instance for method chaining
     */
    public function ungrouped(): self
    {
        $this->query->whereNull('group_id');

        return $this;
    }

    /**
     * Filter tokens with specific ability.
     *
     * @param  string $ability Ability to check for
     * @return self   Current conductor instance for method chaining
     */
    public function withAbility(string $ability): self
    {
        $this->query->where(function ($query) use ($ability): void {
            $query->whereJsonContains('abilities', '*')
                ->orWhereJsonContains('abilities', $ability);
        });

        return $this;
    }

    /**
     * Order tokens by creation date.
     *
     * @param  string $direction Sort direction ('asc' or 'desc')
     * @return self   Current conductor instance for method chaining
     */
    public function orderByCreated(string $direction = 'desc'): self
    {
        $this->query->orderBy('created_at', $direction);

        return $this;
    }

    /**
     * Order tokens by last used date.
     *
     * @param  string $direction Sort direction ('asc' or 'desc')
     * @return self   Current conductor instance for method chaining
     */
    public function orderByLastUsed(string $direction = 'desc'): self
    {
        $this->query->orderBy('last_used_at', $direction);

        return $this;
    }

    /**
     * Limit the number of results.
     *
     * @param  int  $limit Maximum number of results
     * @return self Current conductor instance for method chaining
     */
    public function limit(int $limit): self
    {
        $this->query->limit($limit);

        return $this;
    }

    /**
     * Execute the query and get all results.
     *
     * @return EloquentCollection<int, AccessToken> Collection of matching tokens
     */
    public function get(): EloquentCollection
    {
        /** @var EloquentCollection<int, AccessToken> */
        return $this->query->get();
    }

    /**
     * Execute the query and get the first result.
     *
     * @return null|AccessToken The first matching token or null
     */
    public function first(): ?AccessToken
    {
        /** @var null|AccessToken */
        return $this->query->first();
    }

    /**
     * Execute the query and count the results.
     *
     * @return int Number of matching tokens
     */
    public function count(): int
    {
        return $this->query->count();
    }

    /**
     * Execute the query and check if any results exist.
     *
     * @return bool True if at least one matching token exists
     */
    public function exists(): bool
    {
        return $this->query->exists();
    }

    /**
     * Get the underlying query builder.
     *
     * Allows for custom query modifications not provided by the conductor.
     *
     * @return Builder<AccessToken> The Eloquent query builder
     */
    public function toQuery(): Builder
    {
        return $this->query;
    }
}
