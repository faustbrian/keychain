<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\Exceptions;

use Exception;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class AuditSystemException extends Exception
{
    public static function systemDown(): self
    {
        return new self('Audit system is down');
    }
}
