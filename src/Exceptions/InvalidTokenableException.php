<?php declare(strict_types=1);

/**
 * Copyright (C) Brian Faust
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Cline\Bearer\Exceptions;

use RuntimeException;

/**
 * @author Brian Faust <brian@cline.sh>
 */
final class InvalidTokenableException extends RuntimeException
{
    public static function mustImplementHasApiTokens(): self
    {
        return new self('Tokenable model must implement HasApiTokens interface');
    }
}
