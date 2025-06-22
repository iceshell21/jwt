<?php

declare(strict_types=1);

namespace Iceshell21\Jwt\Exception;

/**
 * Exception thrown when a token has expired.
 * This corresponds to the 'exp' (expiration time) claim.
 */
class ExpiredTokenException extends InvalidTokenException
{
}
