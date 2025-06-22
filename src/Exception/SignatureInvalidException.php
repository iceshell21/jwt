<?php

declare(strict_types=1);

namespace Iceshell21\Jwt\Exception;

/**
 * Exception thrown when a token's signature is invalid.
 */
class SignatureInvalidException extends InvalidTokenException
{
}
