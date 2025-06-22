# PHP JWT Library (iceshell21/jwt)

A simple PHP library for generating and validating JSON Web Tokens (JWTs) without external dependencies for the core JWT logic.

## Features

- Generate JWTs with custom payloads.
- Parse and validate JWTs.
- Support for HS256 signing algorithm by default.
- Customizable token lifetime.
- Custom exceptions for detailed error handling:
    - `InvalidTokenException`
    - `ExpiredTokenException`
    - `BeforeValidTokenException`
    - `SignatureInvalidException`
- PSR-4 autoloading.
- PHPUnit tests.

## Requirements

- PHP 8.0 or higher
- Composer

## Installation

1.  **Require the package using Composer:**

    ```bash
    composer require iceshell21/jwt
    ```
    *(Note: As this is a locally developed package not yet on Packagist, you would typically add it to your `composer.json`repositories section if you were to use it in another local project, or submit it to Packagist.)*

    For local development within this package, after cloning, run:
    ```bash
    composer install
    ```
    This will install development dependencies like PHPUnit.

## Usage

### Initializing the JwtManager

```php
<?php

require 'vendor/autoload.php'; // If installed via Composer

use Iceshell21\Jwt\JwtManager;
use Iceshell21\Jwt\Exception\JwtExceptionInterface; // Catch specific exceptions or the base interface

// Replace 'your-super-secret-key' with a strong, unique secret key
$secretKey = 'your-super-secret-key_for-HS256_must-be-long-and-random';
$algorithm = 'HS256'; // Currently only HS256 is implemented directly
$tokenLifetime = 3600; // 1 hour in seconds

try {
    $jwtManager = new JwtManager($secretKey, $algorithm, $tokenLifetime);
} catch (\InvalidArgumentException $e) {
    // Handle unsupported algorithm or empty secret key
    error_log("Initialization error: " . $e->getMessage());
    // Potentially exit or use a default safe behavior
    exit;
}

```

**Important Security Note:** Your `$secretKey` must be kept confidential and should be cryptographically strong, especially for HS256. Do not hardcode it directly in version-controlled files in production applications; use environment variables or secure configuration management.

### Generating a Token

```php
<?php
// ... (Initialization from above)

$payload = [
    'iss' => 'https://yourdomain.com', // Issuer
    'aud' => 'https://your-api-domain.com', // Audience
    'sub' => 'user123', // Subject (e.g., user ID)
    'username' => 'john.doe',
    'roles' => ['user', 'editor']
    // 'nbf' => time() + 60, // Optional: Not Before claim (token valid in 60 seconds from now)
    // 'exp' is automatically calculated based on lifetime from 'iat' or current time
    // 'iat' is automatically set to current time during generation
];

try {
    $token = $jwtManager->generate($payload);
    echo "Generated Token: " . $token . "\n";

    // You can also override the default lifetime for a specific token
    $shortLivedToken = $jwtManager->generate(['data' => 'temporary_info'], 600); // 10 minutes
    echo "Short-lived Token: " . $shortLivedToken . "\n";

} catch (\JsonException $e) {
    error_log("Error generating token (JSON encoding failed): " . $e->getMessage());
}
```

### Parsing and Validating a Token

The `parse()` method will decode the token and validate its signature, expiration (`exp`), and not-before time (`nbf`). It throws an exception if validation fails.

```php
<?php
// ... (Initialization from above)
// Example: $token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjEyMywidXNlcm5hbWUiOiJ0ZXN0dXNlciIsImlhdCI6MTY3ODg4NjQwMCwibmJmIjoxNjc4ODg2NDAwLCJleHAiOjE2Nzg4OTAwMDB9.some_signature_part";

// Assume $receivedToken is the token you got from a request header, cookie, etc.
// For demonstration, let's generate one:
$receivedToken = $jwtManager->generate(['user_id' => 42, 'username' => 'test']);

use Iceshell21\Jwt\Exception\ExpiredTokenException;
use Iceshell21\Jwt\Exception\InvalidTokenException; // General invalidity (format, claims, etc.)
use Iceshell21\Jwt\Exception\SignatureInvalidException;
use Iceshell21\Jwt\Exception\BeforeValidTokenException;

try {
    $decodedPayload = $jwtManager->parse($receivedToken);

    echo "Token is valid!\n";
    echo "User ID: " . ($decodedPayload->user_id ?? 'N/A') . "\n";
    echo "Username: " . ($decodedPayload->username ?? 'N/A') . "\n";
    // You can now trust $decodedPayload and use its contents
    // var_dump($decodedPayload);

} catch (ExpiredTokenException $e) {
    error_log("Token validation failed: Token has expired. Message: " . $e->getMessage());
    // Handle expired token (e.g., prompt for re-login)
} catch (BeforeValidTokenException $e) {
    error_log("Token validation failed: Token is not yet valid. Message: " . $e->getMessage());
    // Handle token used too early
} catch (SignatureInvalidException $e) {
    error_log("Token validation failed: Signature is invalid. Message: " . $e->getMessage());
    // Handle tampered or incorrectly signed token
} catch (InvalidTokenException $e) {
    // This is a more general exception for other issues like:
    // - Malformed token (wrong number of segments)
    // - Malformed JSON in header or payload
    // - Missing or invalid 'alg' in header
    // - Algorithm in token does not match manager's configured algorithm
    // - Missing 'exp' claim
    // - Invalid 'exp' or 'nbf' claim types (not numeric)
    // - Base64 decoding errors
    error_log("Token validation failed: Token is invalid. Message: " . $e->getMessage());
    // Handle generally invalid token
} catch (\JsonException $e) {
    // This might occur if JSON issues are not caught and wrapped by InvalidTokenException above
    error_log("Token validation failed: JSON processing error during parsing. Message: " . $e->getMessage());
} catch (JwtExceptionInterface $e) {
    // Catch-all for any other library-specific JWT exceptions if not caught above
    error_log("A JWT processing error occurred: " . $e->getMessage());
}
```

### Just Validating a Token (Boolean Check)

If you only need to know if a token is valid without needing the payload immediately or specific error details, you can use the `validate()` method.

```php
<?php
// ... (Initialization from above)
// Assume $token = "some.jwt.token";
$isValid = $jwtManager->validate($receivedToken);

if ($isValid) {
    echo "Token is valid (checked with validate()).\n";
    // If you need the payload now, you would call parse().
    // It's generally safe to call parse() after validate() returns true,
    // but be aware of rare race conditions if the token could expire between calls.
    // For most use cases, if validate() is true, parse() will succeed shortly after.
    // $payload = $jwtManager->parse($receivedToken);
} else {
    echo "Token is invalid (checked with validate()).\n";
    // Note: validate() returning false doesn't tell you *why* it's invalid.
    // If you need the specific reason, you must use parse() within a try-catch block.
}
```

## Supported Algorithms

Currently, the library's direct implementation focuses on `HS256` (HMAC using SHA-256).
The structure (`SUPPORTED_ALGORITHMS` map and `sign`/`verify` methods) allows for adding more algorithms:
1.  Add the algorithm identifier (e.g., `HS384`, `HS512`) and its corresponding PHP `hash_hmac` algorithm name (e.g., `sha384`, `sha512`) to the `SUPPORTED_ALGORITHMS` constant in `JwtManager.php`.
2.  Extend the `switch` statement within the `sign()` method in `JwtManager.php` to map your new JWT algorithm identifier to the PHP internal hash algorithm name.
3.  For asymmetric algorithms (like RS256, ES256), this would be more involved, requiring:
    *   Handling of public and private keys (passed to constructor or sign/verify methods).
    *   Using functions like `openssl_sign()` and `openssl_verify()`.
    *   The `SUPPORTED_ALGORITHMS` map would need to store information about how to handle these (e.g., OpenSSL algorithm constants).

## Running Tests

To run the PHPUnit tests for this package:

1.  Ensure you have installed dev dependencies: `composer install`
2.  Run PHPUnit from the root directory of the package:
    ```bash
    composer test
    ```
    Or directly:
    ```bash
    ./vendor/bin/phpunit
    ```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.
(Standard contribution guidelines like coding standards, tests for new features, etc., would typically be detailed here).

## License

This library is licensed under the MIT License.
(Typically, a `LICENSE` file with the full MIT license text would be included in the repository).
```
