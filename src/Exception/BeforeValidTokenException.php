<?php

declare(strict_types=1);

namespace Iceshell21\Jwt\Exception;

/**
 * Exception thrown when a token is used before its 'nbf' (not before) time.
 */
class BeforeValidTokenException extends InvalidTokenException
{
}
