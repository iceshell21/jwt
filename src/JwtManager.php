<?php

declare(strict_types=1);

namespace Iceshell21\Jwt;

use DateTimeImmutable;
use Iceshell21\Jwt\Exception\BeforeValidTokenException;
use Iceshell21\Jwt\Exception\ExpiredTokenException;
use Iceshell21\Jwt\Exception\InvalidTokenException;
use Iceshell21\Jwt\Exception\JwtExceptionInterface;
use Iceshell21\Jwt\Exception\SignatureInvalidException;
use JsonException; // Added for fully_qualified_strict_types
use InvalidArgumentException; // Added for fully_qualified_strict_types

/**
 * Manages JSON Web Tokens (JWTs).
 *
 * Handles the creation, signing, parsing, and validation of JWTs.
 */
class JwtManager
{
    private const ALGORITHM_HS256 = 'HS256';
    private const ALGORITHM_HS384 = 'HS384';
    private const ALGORITHM_HS512 = 'HS512';

    private const SUPPORTED_ALGORITHMS = [
        self::ALGORITHM_HS256 => 'sha256',
        self::ALGORITHM_HS384 => 'sha384',
        self::ALGORITHM_HS512 => 'sha512',
    ];

    private string $secretKey;
    private string $algorithm;
    private int $defaultLifetime; // in seconds

    /**
     * JwtManager constructor.
     *
     * @param string $secretKey       the secret key used for signing and verifying tokens
     * @param string $algorithm       the signing algorithm to use (e.g., 'HS256')
     * @param int    $defaultLifetime the default lifetime of a token in seconds
     *
     * @throws InvalidArgumentException if the algorithm is not supported or secret key is empty
     */
    public function __construct(string $secretKey, string $algorithm = self::ALGORITHM_HS256, int $defaultLifetime = 3600)
    {
        if (empty($secretKey)) {
            throw new InvalidArgumentException('Secret key cannot be empty.');
        }

        if (! isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException("Unsupported algorithm: {$algorithm}. Supported algorithms are: " . implode(', ', array_keys(self::SUPPORTED_ALGORITHMS)));
        }
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
        $this->defaultLifetime = $defaultLifetime;
    }

    /**
     * Generates a new JWT.
     *
     * @param array<string, mixed> $payload  the payload to include in the token
     * @param ?int                 $lifetime the lifetime of the token in seconds. If null, uses defaultLifetime
     *
     * @return string the generated JWT
     *
     * @throws JsonException if JSON encoding fails
     */
    public function generate(array $payload, ?int $lifetime = null): string
    {
        $effectiveLifetime = $lifetime ?? $this->defaultLifetime;
        $currentTime = new DateTimeImmutable();

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT',
        ];

        $payload['iat'] = $currentTime->getTimestamp(); // Issued At
        $payload['nbf'] = $payload['nbf'] ?? $currentTime->getTimestamp(); // Not Before
        $payload['exp'] = $currentTime->modify("+{$effectiveLifetime} seconds")->getTimestamp(); // Expiration Time

        $encodedHeader = $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR));

        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $signature = $this->sign($signatureInput, $this->secretKey, $this->algorithm);
        $encodedSignature = $this->base64UrlEncode($signature);

        return "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";
    }

    /**
     * Parses and validates a JWT.
     *
     * @param string $token the JWT string
     *
     * @return object the decoded payload as an object
     *
     * @throws InvalidTokenException     if the token format is invalid or claims are missing/invalid
     * @throws SignatureInvalidException if the token signature is invalid
     * @throws ExpiredTokenException     if the token has expired
     * @throws BeforeValidTokenException if the token is not yet valid
     * @throws JsonException             if JSON decoding fails
     */
    public function parse(string $token): object
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new InvalidTokenException('Invalid token format: incorrect number of segments.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        try {
            $headerData = json_decode($this->base64UrlDecode($encodedHeader), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidTokenException('Invalid token header: Malformed JSON.', 0, $e);
        }

        if ($headerData === null || ! isset($headerData['alg']) || ! is_string($headerData['alg'])) {
            throw new InvalidTokenException('Invalid token header: Missing or invalid alg.');
        }

        try {
            $payloadData = json_decode($this->base64UrlDecode($encodedPayload), false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidTokenException('Invalid token payload: Malformed JSON.', 0, $e);
        }

        if ($payloadData === null) { // Should be caught by JsonException, but as a safeguard.
            throw new InvalidTokenException('Invalid token payload: Null after decoding.');
        }

        if (! isset(self::SUPPORTED_ALGORITHMS[$headerData['alg']])) {
            throw new InvalidTokenException("Algorithm '{$headerData['alg']}' present in token header is not supported by this manager.");
        }

        if ($headerData['alg'] !== $this->algorithm) {
            throw new InvalidTokenException("Token algorithm '{$headerData['alg']}' does not match manager's configured algorithm '{$this->algorithm}'.");
        }

        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $expectedSignature = $this->base64UrlDecode($encodedSignature);

        if (! $this->verify($signatureInput, $expectedSignature, $this->secretKey, $headerData['alg'])) {
            throw new SignatureInvalidException('Token signature verification failed.');
        }

        $currentTime = (new DateTimeImmutable())->getTimestamp();

        if (isset($payloadData->nbf)) {
            if (! is_numeric($payloadData->nbf)) {
                throw new InvalidTokenException('Invalid nbf claim: Must be a numeric timestamp.');
            }

            if ($payloadData->nbf > $currentTime) {
                throw new BeforeValidTokenException('Token is not yet valid (nbf).');
            }
        }

        if (! isset($payloadData->exp)) {
            throw new InvalidTokenException('Token has no expiration (exp) claim.');
        }

        if (! is_numeric($payloadData->exp)) {
            throw new InvalidTokenException('Invalid exp claim: Must be a numeric timestamp.');
        }

        if ($payloadData->exp <= $currentTime) {
            throw new ExpiredTokenException('Token has expired (exp).');
        }

        return $payloadData;
    }

    /**
     * Validates a token.
     *
     * @param string $token the JWT to validate
     *
     * @return bool true if the token is valid, false otherwise
     */
    public function validate(string $token): bool
    {
        try {
            $this->parse($token);

            return true;
        } catch (JwtExceptionInterface $e) { // Catching our own base JWT exception interface
            // Log the exception if needed, e.g., error_log($e->getMessage());
            return false;
        } catch (JsonException $e) { // Catching potential JsonExceptions not wrapped by parse
            // Log JSON specific errors
            return false;
        }
    }

    /**
     * Base64 URL encodes a string.
     *
     * @param string $data the string to encode
     *
     * @return string the Base64 URL encoded string
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decodes a string.
     *
     * @param string $data the Base64 URL encoded string
     *
     * @return string the decoded string
     */
    private function base64UrlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            // This can happen if $data is not valid base64 or contains characters not in the alphabet
            throw new InvalidTokenException('Base64Url decoding failed. Input data may be corrupted or not properly encoded.');
        }

        return $decoded;
    }

    /**
     * Signs data using the specified algorithm and key.
     *
     * @param string $data      the data to sign
     * @param string $key       the secret key
     * @param string $algorithm the algorithm to use (e.g., 'HS256')
     *
     * @return string the raw signature
     *
     * @throws InvalidArgumentException if the algorithm is not supported for signing
     */
    private function sign(string $data, string $key, string $algorithm): string
    {
        if (! isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            // This should ideally be caught by constructor or header check, but good for defense.
            // The constructor already validates the algorithm for the manager instance.
            // This check here is more for the algorithm specified in a token being parsed,
            // if sign is called by verify.
            throw new InvalidArgumentException("Unsupported signing algorithm: {$algorithm}");
        }

        $phpHashAlgorithm = self::SUPPORTED_ALGORITHMS[$algorithm];

        // All currently supported algorithms (HS256, HS384, HS512) use hash_hmac.
        // If other types of algorithms were added (e.g., RSA, EC), a switch or more complex logic
        // would be needed here to determine whether to use hash_hmac, openssl_sign, etc.
        return hash_hmac($phpHashAlgorithm, $data, $key, true);
    }

    /**
     * Verifies a signature.
     *
     * @param string $data      the data that was signed
     * @param string $signature the signature to verify (raw binary)
     * @param string $key       the secret key
     * @param string $algorithm the algorithm used for signing
     *
     * @return bool true if the signature is valid, false otherwise
     *
     * @throws InvalidArgumentException if the algorithm is not supported for verification
     */
    private function verify(string $data, string $signature, string $key, string $algorithm): bool
    {
        if (! isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new InvalidArgumentException("Unsupported verification algorithm: {$algorithm}");
        }

        $expectedSignature = $this->sign($data, $key, $algorithm); // Use internal sign method

        return hash_equals($expectedSignature, $signature);
    }
}
