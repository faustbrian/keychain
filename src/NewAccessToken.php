<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer;

use Cline\Bearer\Database\Models\AccessToken;
use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * Data transfer object for newly created access tokens.
 *
 * Encapsulates a newly created personal access token along with its
 * plain-text representation. The plain-text token is only available
 * at creation time and cannot be retrieved later.
 *
 * @implements Arrayable<string, mixed>
 *
 * @author Brian Faust <brian@cline.sh>
 *
 * @psalm-immutable
 */
final readonly class NewAccessToken implements Arrayable, JsonSerializable
{
    /**
     * Create a new access token result.
     *
     * @param AccessToken $accessToken    The persisted token model instance
     * @param string      $plainTextToken The unhashed token string (only available once)
     */
    public function __construct(
        public AccessToken $accessToken,
        public string $plainTextToken,
    ) {}

    /**
     * Get the instance as an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'accessToken' => $this->accessToken,
            'plainTextToken' => $this->plainTextToken,
        ];
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
