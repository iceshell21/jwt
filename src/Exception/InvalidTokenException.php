<?php

declare(strict_types=1);

namespace Iceshell21\Jwt\Exception;

use RuntimeException; // Added for fully_qualified_strict_types

/**
 * Exception thrown when a token is invalid for reasons other than signature, expiration, or not-before time.
 * For example, malformed token, incorrect number of segments, invalid JSON, missing claims.
 */
class InvalidTokenException extends RuntimeException implements JwtExceptionInterface {}
