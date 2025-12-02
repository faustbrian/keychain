<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Database\Models\AccessTokenGroup;
use Cline\Bearer\Enums\PrimaryKeyType;
use Cline\Bearer\Exceptions\InvalidPrimaryKeyValueException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

describe('HasBearerPrimaryKey', function (): void {
    // Helper to recreate table with specific primary key type
    function recreateAccessTokensTable(PrimaryKeyType $primaryKeyType): void
    {
        $tableName = config('bearer.table_names.access_tokens', 'access_tokens');

        Schema::dropIfExists($tableName);

        Schema::create($tableName, function (Blueprint $table) use ($primaryKeyType): void {
            match ($primaryKeyType) {
                PrimaryKeyType::ULID => $table->ulid('id')->primary(),
                PrimaryKeyType::UUID => $table->uuid('id')->primary(),
                PrimaryKeyType::Id => $table->id(),
            };

            $table->string('owner_type')->nullable();
            $table->unsignedBigInteger('owner_id')->nullable();
            $table->string('type', 32);
            $table->string('environment', 32);
            $table->string('name');
            $table->string('token', 64)->unique();
            $table->string('prefix', 32);
            $table->json('abilities')->nullable();
            $table->json('metadata')->nullable();
            $table->json('allowed_ips')->nullable();
            $table->json('allowed_domains')->nullable();
            $table->unsignedInteger('rate_limit_per_minute')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    // Helper to recreate access_token_groups table with specific primary key type
    function recreateAccessTokenGroupsTable(PrimaryKeyType $primaryKeyType): void
    {
        $tableName = config('bearer.table_names.access_token_groups', 'access_token_groups');

        Schema::dropIfExists($tableName);

        Schema::create($tableName, function (Blueprint $table) use ($primaryKeyType): void {
            match ($primaryKeyType) {
                PrimaryKeyType::ULID => $table->ulid('id')->primary(),
                PrimaryKeyType::UUID => $table->uuid('id')->primary(),
                PrimaryKeyType::Id => $table->id(),
            };

            $table->string('owner_type')->nullable();
            $table->unsignedBigInteger('owner_id')->nullable();
            $table->string('name')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
        });
    }

    describe('getIncrementing', function (): void {
        test('returns false when using UUID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'uuid');
            $token = new AccessToken();

            // Act
            $result = $token->getIncrementing();

            // Assert
            expect($result)->toBeFalse();
        });

        test('returns false when using ULID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'ulid');
            $token = new AccessToken();

            // Act
            $result = $token->getIncrementing();

            // Assert
            expect($result)->toBeFalse();
        });

        test('returns true when using standard incrementing ID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'id');
            $token = new AccessToken();

            // Act
            $result = $token->getIncrementing();

            // Assert
            expect($result)->toBeTrue();
        });

        test('returns true for default incrementing behavior with no config', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'id');
            $group = new AccessTokenGroup();

            // Act
            $result = $group->getIncrementing();

            // Assert
            expect($result)->toBeTrue();
        });
    });

    describe('getKeyType', function (): void {
        test('returns string when using UUID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'uuid');
            $token = new AccessToken();

            // Act
            $result = $token->getKeyType();

            // Assert
            expect($result)->toBe('string');
        });

        test('returns string when using ULID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'ulid');
            $token = new AccessToken();

            // Act
            $result = $token->getKeyType();

            // Assert
            expect($result)->toBe('string');
        });

        test('returns int when using standard ID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'id');
            $token = new AccessToken();

            // Act
            $result = $token->getKeyType();

            // Assert
            expect($result)->toBe('int');
        });
    });

    describe('newUniqueId', function (): void {
        test('generates UUID value from PrimaryKeyGenerator', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'uuid');
            $token = new AccessToken();

            // Act
            $result = $token->newUniqueId();

            // Assert
            expect($result)->toBeString();
            expect($result)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/');
        });

        test('generates ULID value from PrimaryKeyGenerator', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'ulid');
            $token = new AccessToken();

            // Act
            $result = $token->newUniqueId();

            // Assert
            expect($result)->toBeString();
            expect($result)->toHaveLength(26);
        });

        test('returns null for standard ID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'id');
            $token = new AccessToken();

            // Act
            $result = $token->newUniqueId();

            // Assert
            expect($result)->toBeNull();
        });
    });

    describe('uniqueIds', function (): void {
        test('returns empty array for PrimaryKeyType::Id', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'id');
            $token = new AccessToken();

            // Act
            $result = $token->uniqueIds();

            // Assert
            expect($result)->toBeArray();
            expect($result)->toBeEmpty();
        });

        test('returns array with key name for UUID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'uuid');
            $token = new AccessToken();

            // Act
            $result = $token->uniqueIds();

            // Assert
            expect($result)->toBe(['id']);
        });

        test('returns array with key name for ULID primary key type', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'ulid');
            $token = new AccessToken();

            // Act
            $result = $token->uniqueIds();

            // Assert
            expect($result)->toBe(['id']);
        });

        test('handles custom primary key name', function (): void {
            // Arrange
            Config::set('bearer.primary_key_type', 'uuid');
            $group = new AccessTokenGroup();

            // Act
            $result = $group->uniqueIds();

            // Assert
            expect($result)->toBe(['id']);
        });
    });

    describe('bootHasBearerPrimaryKey', function (): void {
        describe('auto-generation', function (): void {
            test('auto-generates UUID when not set', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act
                $token = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);

                // Assert
                expect($token->id)->toBeString();
                expect($token->id)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/');
            });

            test('auto-generates ULID when not set', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act
                $token = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);

                // Assert
                expect($token->id)->toBeString();
                expect($token->id)->toHaveLength(26);
            });

            test('does not auto-generate for standard ID type', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'id');
                recreateAccessTokensTable(PrimaryKeyType::Id);
                $user = createUser();

                // Act
                $token = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);

                // Assert
                expect($token->id)->toBeInt();
                expect($token->id)->toBeGreaterThan(0);
            });

            test('uses manually set UUID value when provided as string', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();
                $customUuid = '550e8400-e29b-41d4-a716-446655440000';

                // Create model and manually set ID before save
                $token = new AccessToken([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);
                $token->id = $customUuid;
                $token->save();

                // Assert
                expect($token->id)->toBe($customUuid);
            });

            test('uses manually set ULID value when provided as string', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();
                $customUlid = '01arz3ndektsv4rrffq69g5fav';

                // Create model and manually set ID before save
                $token = new AccessToken([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);
                $token->id = $customUlid;
                $token->save();

                // Assert
                expect($token->id)->toBe($customUlid);
            });
        });

        describe('validation', function (): void {
            test('throws InvalidPrimaryKeyValueException for non-string UUID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act & Assert
                $testFn = function () use ($user): void {
                    $token = new AccessToken([
                        'owner_type' => $user::class,
                        'owner_id' => $user->id,
                        'type' => 'sk',
                        'environment' => 'test',
                        'name' => 'Test Token',
                        'token' => 'hashed_token',
                        'prefix' => 'sk_test',
                        'abilities' => ['*'],
                    ]);
                    $token->id = 12_345; // Set non-string value
                    $token->save();
                };

                expect($testFn)->toThrow(InvalidPrimaryKeyValueException::class, 'Cannot assign non-string value to UUID primary key. Got: integer');
            });

            test('throws InvalidPrimaryKeyValueException for non-string ULID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act & Assert
                $testFn = function () use ($user): void {
                    $token = new AccessToken([
                        'owner_type' => $user::class,
                        'owner_id' => $user->id,
                        'type' => 'sk',
                        'environment' => 'test',
                        'name' => 'Test Token',
                        'token' => 'hashed_token',
                        'prefix' => 'sk_test',
                        'abilities' => ['*'],
                    ]);
                    $token->id = 12_345; // Set non-string value
                    $token->save();
                };

                expect($testFn)->toThrow(InvalidPrimaryKeyValueException::class, 'Cannot assign non-string value to ULID primary key. Got: integer');
            });

            test('throws InvalidPrimaryKeyValueException for array UUID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act & Assert
                $testFn = function () use ($user): void {
                    $token = new AccessToken([
                        'owner_type' => $user::class,
                        'owner_id' => $user->id,
                        'type' => 'sk',
                        'environment' => 'test',
                        'name' => 'Test Token',
                        'token' => 'hashed_token',
                        'prefix' => 'sk_test',
                        'abilities' => ['*'],
                    ]);
                    $token->id = ['invalid']; // Set array value
                    $token->save();
                };

                expect($testFn)->toThrow(InvalidPrimaryKeyValueException::class, 'Cannot assign non-string value to UUID primary key. Got: array');
            });

            test('throws InvalidPrimaryKeyValueException for object ULID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act & Assert
                $testFn = function () use ($user): void {
                    $token = new AccessToken([
                        'owner_type' => $user::class,
                        'owner_id' => $user->id,
                        'type' => 'sk',
                        'environment' => 'test',
                        'name' => 'Test Token',
                        'token' => 'hashed_token',
                        'prefix' => 'sk_test',
                        'abilities' => ['*'],
                    ]);
                    $token->id = new stdClass(); // Set object value
                    $token->save();
                };

                expect($testFn)->toThrow(InvalidPrimaryKeyValueException::class, 'Cannot assign non-string value to ULID primary key. Got: object');
            });

            test('auto-generates when empty string provided for UUID type', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act
                $token = new AccessToken([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);
                $token->id = ''; // Empty string is falsy, will auto-generate
                $token->save();

                // Assert
                expect($token->id)->toBeString();
                expect($token->id)->not->toBe('');
                expect($token->id)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/');
            });

            test('auto-generates when empty string provided for ULID type', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act
                $token = new AccessToken([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Test Token',
                    'token' => 'hashed_token',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);
                $token->id = ''; // Empty string is falsy, will auto-generate
                $token->save();

                // Assert
                expect($token->id)->toBeString();
                expect($token->id)->not->toBe('');
                expect($token->id)->toHaveLength(26);
            });
        });

        describe('edge cases', function (): void {
            test('works with AccessTokenGroup model using UUID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokenGroupsTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act
                $group = AccessTokenGroup::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'name' => 'Test Group',
                ]);

                // Assert
                expect($group->id)->toBeString();
                expect($group->id)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/');
            });

            test('works with AccessTokenGroup model using ULID', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokenGroupsTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act
                $group = AccessTokenGroup::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'name' => 'Test Group',
                ]);

                // Assert
                expect($group->id)->toBeString();
                expect($group->id)->toHaveLength(26);
            });

            test('handles config fallback to default when invalid type provided', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'invalid');
                $token = new AccessToken();

                // Act
                $result = $token->uniqueIds();

                // Assert
                expect($result)->toBeEmpty();
            });

            test('generates unique UUIDs for multiple tokens', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'uuid');
                recreateAccessTokensTable(PrimaryKeyType::UUID);
                $user = createUser();

                // Act
                $token1 = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Token 1',
                    'token' => 'hashed_token_1',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);

                $token2 = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'pk',
                    'environment' => 'test',
                    'name' => 'Token 2',
                    'token' => 'hashed_token_2',
                    'prefix' => 'pk_test',
                    'abilities' => ['*'],
                ]);

                // Assert
                expect($token1->id)->toBeString();
                expect($token2->id)->toBeString();
                expect($token1->id)->not->toBe($token2->id);
            });

            test('generates unique ULIDs for multiple tokens', function (): void {
                // Arrange
                Config::set('bearer.primary_key_type', 'ulid');
                recreateAccessTokensTable(PrimaryKeyType::ULID);
                $user = createUser();

                // Act
                $token1 = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'sk',
                    'environment' => 'test',
                    'name' => 'Token 1',
                    'token' => 'hashed_token_1',
                    'prefix' => 'sk_test',
                    'abilities' => ['*'],
                ]);

                $token2 = AccessToken::query()->create([
                    'owner_type' => $user::class,
                    'owner_id' => $user->id,
                    'type' => 'pk',
                    'environment' => 'test',
                    'name' => 'Token 2',
                    'token' => 'hashed_token_2',
                    'prefix' => 'pk_test',
                    'abilities' => ['*'],
                ]);

                // Assert
                expect($token1->id)->toBeString();
                expect($token2->id)->toBeString();
                expect($token1->id)->not->toBe($token2->id);
            });
        });
    });
});
