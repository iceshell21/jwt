<?php

declare(strict_types=1);

namespace Iceshell21\Jwt;

use DateTimeImmutable;
use Iceshell21\Jwt\Exception\ExpiredTokenException;
use Iceshell21\Jwt\Exception\InvalidTokenException;
use Iceshell21\Jwt\Exception\SignatureInvalidException;
use Iceshell21\Jwt\Exception\BeforeValidTokenException;
use Iceshell21\Jwt\Exception\JwtExceptionInterface;

/**
 * Manages JSON Web Tokens (JWTs).
 *
 * Handles the creation, signing, parsing, and validation of JWTs.
 */
class JwtManager
{
    private const ALGORITHM_HS256 = 'HS256';
    private const SUPPORTED_ALGORITHMS = [
        self::ALGORITHM_HS256 => 'hash_hmac_sha256',
        // Add other algorithms here, e.g., 'HS384' => 'hash_hmac_sha384', 'HS512' => 'hash_hmac_sha512'
    ];

    private string $secretKey;
    private string $algorithm;
    private int $defaultLifetime; // in seconds

    /**
     * JwtManager constructor.
     *
     * @param string $secretKey The secret key used for signing and verifying tokens.
     * @param string $algorithm The signing algorithm to use (e.g., 'HS256').
     * @param int $defaultLifetime The default lifetime of a token in seconds.
     * @throws \InvalidArgumentException If the algorithm is not supported or secret key is empty.
     */
    public function __construct(string $secretKey, string $algorithm = self::ALGORITHM_HS256, int $defaultLifetime = 3600)
    {
        if (empty($secretKey)) {
            throw new \InvalidArgumentException('Secret key cannot be empty.');
        }
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            throw new \InvalidArgumentException("Unsupported algorithm: {$algorithm}. Supported algorithms are: " . implode(', ', array_keys(self::SUPPORTED_ALGORITHMS)));
        }
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
        $this->defaultLifetime = $defaultLifetime;
    }

    /**
     * Generates a new JWT.
     *
     * @param array<string, mixed> $payload The payload to include in the token.
     * @param ?int $lifetime The lifetime of the token in seconds. If null, uses defaultLifetime.
     * @return string The generated JWT.
     * @throws \JsonException If JSON encoding fails.
     */
    public function generate(array $payload, ?int $lifetime = null): string
    {
        $effectiveLifetime = $lifetime ?? $this->defaultLifetime;
        $currentTime = new DateTimeImmutable();

        $header = [
            'alg' => $this->algorithm,
            'typ' => 'JWT'
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
     * @param string $token The JWT string.
     * @return object The decoded payload as an object.
     * @throws InvalidTokenException If the token format is invalid or claims are missing/invalid.
     * @throws SignatureInvalidException If the token signature is invalid.
     * @throws ExpiredTokenException If the token has expired.
     * @throws BeforeValidTokenException If the token is not yet valid.
     * @throws \JsonException If JSON decoding fails.
     */
    public function parse(string $token): object
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('Invalid token format: incorrect number of segments.');
        }

        list($encodedHeader, $encodedPayload, $encodedSignature) = $parts;

        try {
            $headerData = json_decode($this->base64UrlDecode($encodedHeader), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidTokenException('Invalid token header: Malformed JSON.', 0, $e);
        }

        if ($headerData === null || !isset($headerData['alg']) || !is_string($headerData['alg'])) {
            throw new InvalidTokenException('Invalid token header: Missing or invalid alg.');
        }

        try {
            $payloadData = json_decode($this->base64UrlDecode($encodedPayload), false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new InvalidTokenException('Invalid token payload: Malformed JSON.', 0, $e);
        }
        if ($payloadData === null) { // Should be caught by JsonException, but as a safeguard.
            throw new InvalidTokenException('Invalid token payload: Null after decoding.');
        }

        if (!isset(self::SUPPORTED_ALGORITHMS[$headerData['alg']])) {
            throw new InvalidTokenException("Algorithm '{$headerData['alg']}' present in token header is not supported by this manager.");
        }

        if ($headerData['alg'] !== $this->algorithm) {
            throw new InvalidTokenException("Token algorithm '{$headerData['alg']}' does not match manager's configured algorithm '{$this->algorithm}'.");
        }

        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $expectedSignature = $this->base64UrlDecode($encodedSignature);

        if (!$this->verify($signatureInput, $expectedSignature, $this->secretKey, $headerData['alg'])) {
            throw new SignatureInvalidException('Token signature verification failed.');
        }

        $currentTime = (new DateTimeImmutable())->getTimestamp();

        if (isset($payloadData->nbf)) {
            if (!is_numeric($payloadData->nbf)) {
                throw new InvalidTokenException('Invalid nbf claim: Must be a numeric timestamp.');
            }
            if ($payloadData->nbf > $currentTime) {
                throw new BeforeValidTokenException('Token is not yet valid (nbf).');
            }
        }

        if (!isset($payloadData->exp)) {
            throw new InvalidTokenException('Token has no expiration (exp) claim.');
        }
        if (!is_numeric($payloadData->exp)) {
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
     * @param string $token The JWT to validate.
     * @return bool True if the token is valid, false otherwise.
     */
    public function validate(string $token): bool
    {
        try {
            $this->parse($token);
            return true;
        } catch (JwtExceptionInterface $e) { // Catching our own base JWT exception interface
            // Log the exception if needed, e.g., error_log($e->getMessage());
            return false;
        } catch (\JsonException $e) { // Catching potential JsonExceptions not wrapped by parse
            // Log JSON specific errors
            return false;
        }
    }

    /**
     * Base64 URL encodes a string.
     *
     * @param string $data The string to encode.
     * @return string The Base64 URL encoded string.
     */
    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decodes a string.
     *
     * @param string $data The Base64 URL encoded string.
     * @return string The decoded string.
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
     * @param string $data The data to sign.
     * @param string $key The secret key.
     * @param string $algorithm The algorithm to use (e.g., 'HS256').
     * @return string The raw signature.
     * @throws \InvalidArgumentException If the algorithm is not supported for signing.
     */
    private function sign(string $data, string $key, string $algorithm): string
    {
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
            // This should ideally be caught by constructor or header check, but good for defense.
            throw new \InvalidArgumentException("Unsupported signing algorithm: {$algorithm}");
        }

        $phpAlgorithm = '';
        switch ($algorithm) {
            case self::ALGORITHM_HS256:
                $phpAlgorithm = 'sha256';
                break;
            // Add cases for HS384, HS512 if they are added to SUPPORTED_ALGORITHMS
            // e.g. case 'HS384': $phpAlgorithm = 'sha384'; break;
            default:
                throw new \InvalidArgumentException("Algorithm '{$algorithm}' has no defined hash function for signing in this manager.");
        }

        return hash_hmac($phpAlgorithm, $data, $key, true);
    }

    /**
     * Verifies a signature.
     *
     * @param string $data The data that was signed.
     * @param string $signature The signature to verify (raw binary).
     * @param string $key The secret key.
     * @param string $algorithm The algorithm used for signing.
     * @return bool True if the signature is valid, false otherwise.
     * @throws \InvalidArgumentException If the algorithm is not supported for verification.
     */
    private function verify(string $data, string $signature, string $key, string $algorithm): bool
    {
        if (!isset(self::SUPPORTED_ALGORITHMS[$algorithm])) {
             throw new \InvalidArgumentException("Unsupported verification algorithm: {$algorithm}");
        }

        $expectedSignature = $this->sign($data, $key, $algorithm); // Use internal sign method
        return hash_equals($expectedSignature, $signature);
    }
}
