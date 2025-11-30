<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Console\Commands;

use Cline\Bearer\Database\Models\AccessToken;
use Cline\Bearer\Facades\Bearer;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;

use function assert;
use function is_int;
use function now;
use function sprintf;

/**
 * Console command to prune expired and revoked tokens from the database.
 *
 * This command removes personal access tokens that have been expired or revoked
 * for longer than a specified time period. Regular pruning helps maintain
 * database performance and removes unnecessary token records.
 *
 * @author Brian Faust <brian@cline.sh>
 */
final class PruneExpiredCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'bearer:prune-expired
                            {--hours= : Prune tokens expired more than this many hours ago}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune expired personal access tokens from the database';

    /**
     * Execute the console command.
     *
     * Removes personal access tokens that have been expired or revoked for
     * longer than the configured time period. This helps maintain database
     * performance by cleaning up stale token records.
     *
     * @return int Command exit code (0 for success)
     */
    public function handle(): int
    {
        /** @var int */
        $hours = $this->option('hours') ?? Config::get('bearer.prune.expired_hours', 24);

        /** @var class-string<AccessToken> $model */
        $model = Bearer::personalAccessTokenModel();

        $count = $model::query()
            ->where(function ($query) use ($hours): void {
                $query->where('expires_at', '<', now()->subHours($hours))
                    ->orWhere('revoked_at', '<', now()->subHours($hours));
            })
            ->delete();

        assert(is_int($count));

        $this->components->info(sprintf('Pruned %s expired/revoked tokens.', $count));

        return self::SUCCESS;
    }
}
