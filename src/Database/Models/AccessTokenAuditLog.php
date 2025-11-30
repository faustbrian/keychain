<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Database\Models;

use Cline\Bearer\Database\Concerns\HasBearerPrimaryKey;
use Cline\Bearer\Database\Factories\AccessTokenAuditLogFactory;
use Cline\Bearer\Enums\AuditEvent;
use Illuminate\Database\Eloquent\Attributes\UseFactory;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Override;

use function array_key_exists;
use function now;

/**
 * Eloquent model representing audit log entries for token events.
 *
 * Records significant events in a token's lifecycle for security, compliance,
 * and debugging purposes. Each log entry captures the event type, associated
 * token, request metadata, and timestamp.
 *
 * @property Carbon                    $created_at Event timestamp
 * @property AuditEvent                $event      Type of audit event
 * @property mixed                     $id         Primary key (auto-increment, UUID, or ULID)
 * @property null|string               $ip_address IP address from which the event occurred
 * @property null|array<string, mixed> $metadata   Optional arbitrary event metadata
 * @property null|AccessToken          $token      The token this log entry belongs to
 * @property int|string                $token_id   Foreign key to the access_tokens table
 * @property null|string               $user_agent User agent string from the request
 *
 * @author Brian Faust <brian@cline.sh>
 */
#[UseFactory(AccessTokenAuditLogFactory::class)]
final class AccessTokenAuditLog extends Model
{
    /** @use HasFactory<Factory<static>> */
    use HasFactory;
    use HasBearerPrimaryKey;

    /**
     * Indicates if the model should use timestamps.
     *
     * We only track creation time for audit logs, not updates.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that should be cast to native types.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'event' => AuditEvent::class,
        'metadata' => 'json',
        'created_at' => 'datetime',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'token_id',
        'event',
        'ip_address',
        'user_agent',
        'metadata',
        'created_at',
    ];

    /**
     * Get the table name from configuration.
     *
     * Retrieves the access_token_audit_logs table name from the Bearer configuration,
     * defaulting to 'access_token_audit_logs' if not configured.
     *
     * @return string The table name for audit log storage
     */
    #[Override()]
    public function getTable(): string
    {
        /** @var string */
        return Config::get('bearer.table_names.access_token_audit_logs', 'access_token_audit_logs');
    }

    /**
     * Get the token this audit log entry belongs to.
     *
     * Defines the relationship to the AccessToken being audited.
     *
     * @return BelongsTo<AccessToken, $this> The relationship to the token
     */
    public function token(): BelongsTo
    {
        return $this->belongsTo(AccessToken::class, 'token_id');
    }

    /**
     * Boot the model.
     *
     * Automatically sets the created_at timestamp when creating audit logs
     * since we disabled automatic timestamps.
     */
    #[Override()]
    protected static function boot(): void
    {
        parent::boot();

        self::creating(function (self $model): void {
            if (!array_key_exists('created_at', $model->attributes)) {
                $model->created_at = now();
            }
        });
    }
}
