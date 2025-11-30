<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Database;

use Cline\Morpheus\MorphKeyRegistry;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Database\Eloquent\Model;

/**
 * Registry for managing polymorphic relationship key mappings.
 *
 * This registry allows you to configure which primary key column should be used
 * for each model type in polymorphic relationships. This is particularly useful
 * when different models use different key types (e.g., User with 'uuid', Team with 'id').
 *
 * Morph key functionality is delegated to the Morpheus MorphKeyRegistry package,
 * providing a facade for Bearer-specific polymorphic key management.
 *
 * Example usage:
 * ```php
 * $registry = app(ModelRegistry::class);
 *
 * // Map models to their primary key columns
 * $registry->morphKeyMap([
 *     User::class => 'uuid',
 *     Team::class => 'id',
 *     Organization::class => 'ulid',
 * ]);
 *
 * // Or enforce mappings (throws if model not mapped)
 * $registry->enforceMorphKeyMap([
 *     User::class => 'uuid',
 * ]);
 * ```
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
#[Singleton()]
final readonly class ModelRegistry
{
    /**
     * Create a new ModelRegistry instance.
     *
     * @param MorphKeyRegistry $morphKeyRegistry The shared morph key registry from Morpheus
     *                                           that handles the actual key mapping logic
     */
    public function __construct(
        private MorphKeyRegistry $morphKeyRegistry,
    ) {}

    /**
     * Register polymorphic key mappings.
     *
     * Establishes which primary key column should be used for each model
     * class in polymorphic relationships. This is a soft mapping that
     * doesn't throw exceptions for unmapped models.
     *
     * @param array<class-string, string> $map Model class => column name mappings
     *                                         (e.g., [User::class => 'uuid', Team::class => 'id'])
     */
    public function morphKeyMap(array $map): void
    {
        $this->morphKeyRegistry->map($map);
    }

    /**
     * Register polymorphic key mappings and enforce their usage.
     *
     * Similar to morphKeyMap(), but throws exceptions when attempting to use
     * models that haven't been explicitly mapped. Use this for strict type
     * safety in polymorphic relationships.
     *
     * @param array<class-string, string> $map Model class => column name mappings
     *                                         (e.g., [User::class => 'uuid'])
     */
    public function enforceMorphKeyMap(array $map): void
    {
        $this->morphKeyRegistry->enforce($map);
    }

    /**
     * Enable strict enforcement of key mappings.
     *
     * After calling this method, all polymorphic key lookups will require
     * an explicit mapping. Useful for ensuring all models are properly
     * configured before being used in production.
     */
    public function requireKeyMap(): void
    {
        $this->morphKeyRegistry->requireMapping();
    }

    /**
     * Get the polymorphic key column name for a model instance.
     *
     * Retrieves the configured primary key column for the given model.
     * Falls back to the model's getKeyName() if no mapping exists.
     *
     * @param  Model  $model The model instance to get the key for
     * @return string The primary key column name (e.g., 'id', 'uuid', 'ulid')
     */
    public function getModelKey(Model $model): string
    {
        return $this->morphKeyRegistry->getKey($model);
    }

    /**
     * Get the polymorphic key column name from a model class string.
     *
     * Retrieves the configured primary key column for a model class without
     * instantiating the model. Useful for eager loading and query building.
     *
     * @param  class-string $class The model class name
     * @return string       The primary key column name (e.g., 'id', 'uuid', 'ulid')
     */
    public function getModelKeyFromClass(string $class): string
    {
        return $this->morphKeyRegistry->getKeyFromClass($class);
    }

    /**
     * Reset all registry state.
     *
     * Clears all registered mappings and enforcement settings. Primarily
     * useful for testing to ensure a clean state between test runs.
     */
    public function reset(): void
    {
        $this->morphKeyRegistry->reset();
    }
}
