<?php

declare(strict_types=1);

namespace Iceshell21\Jwt\Tests;

use DateTimeImmutable;
use Iceshell21\Jwt\Exception\BeforeValidTokenException;
use Iceshell21\Jwt\Exception\ExpiredTokenException;
use Iceshell21\Jwt\Exception\InvalidTokenException;
use Iceshell21\Jwt\Exception\JwtExceptionInterface; // Keep if used, remove if not
use Iceshell21\Jwt\Exception\SignatureInvalidException;
use Iceshell21\Jwt\JwtManager;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class JwtManagerTest extends TestCase
{
    private const TEST_SECRET = 'your-very-secure-secret-key-for-testing-only';
    private const ALT_SECRET = 'another-different-secret-key-for-testing';
    private const DEFAULT_LIFETIME = 3600;

    private JwtManager $jwtManager;

    protected function setUp(): void
    {
        $this->jwtManager = new JwtManager(self::TEST_SECRET, 'HS256', self::DEFAULT_LIFETIME);
    }

    public function testGenerateAndParseTokenSuccessfully(): void
    {
        $payload = ['uid' => 123, 'username' => 'testuser', 'data' => ['foo' => 'bar']];
        $token = $this->jwtManager->generate($payload);

        $this->assertNotEmpty($token);
        $this->assertIsString($token);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/', $token);

        $decodedPayload = $this->jwtManager->parse($token);

        $this->assertIsObject($decodedPayload);
        $this->assertEquals($payload['uid'], $decodedPayload->uid);
        $this->assertEquals($payload['username'], $decodedPayload->username);
        $this->assertEquals($payload['data']['foo'], $decodedPayload->data->foo);
        $this->assertObjectHasAttribute('iat', $decodedPayload);
        $this->assertObjectHasAttribute('nbf', $decodedPayload);
        $this->assertObjectHasAttribute('exp', $decodedPayload);
        $this->assertGreaterThanOrEqual(time(), $decodedPayload->exp);
        $this->assertLessThanOrEqual(time() + self::DEFAULT_LIFETIME, $decodedPayload->exp);
        $this->assertEquals($decodedPayload->iat, $decodedPayload->nbf); // Default nbf is iat
    }

    public function testGenerateTokenWithCustomLifetime(): void
    {
        $lifetime = 600; // 10 minutes
        $payload = ['data' => 'custom_lifetime'];
        $token = $this->jwtManager->generate($payload, $lifetime);
        $decodedPayload = $this->jwtManager->parse($token);
        $this->assertLessThanOrEqual(time() + $lifetime, $decodedPayload->exp);
        $this->assertGreaterThanOrEqual(time() + $lifetime - 5, $decodedPayload->exp); // Allow 5s leeway
    }

    public function testGenerateAndParseTokenWithHS384(): void
    {
        $manager = new JwtManager(self::TEST_SECRET, 'HS384', self::DEFAULT_LIFETIME);
        $payload = ['data' => 'hs384 test', 'uid' => 384];
        $token = $manager->generate($payload);

        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/', $token);

        $decodedPayload = $manager->parse($token);
        $this->assertEquals('hs384 test', $decodedPayload->data);
        $this->assertEquals(384, $decodedPayload->uid);

        // Test validation with a manager configured for HS256 fails
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token algorithm 'HS384' does not match manager's configured algorithm 'HS256'.");
        $this->jwtManager->parse($token); // jwtManager is configured for HS256
    }

    public function testGenerateAndParseTokenWithHS512(): void
    {
        $manager = new JwtManager(self::TEST_SECRET, 'HS512', self::DEFAULT_LIFETIME);
        $payload = ['data' => 'hs512 test', 'uid' => 512];
        $token = $manager->generate($payload);

        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/', $token);

        $decodedPayload = $manager->parse($token);
        $this->assertEquals('hs512 test', $decodedPayload->data);
        $this->assertEquals(512, $decodedPayload->uid);

        // Test validation with a manager configured for HS256 fails
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token algorithm 'HS512' does not match manager's configured algorithm 'HS256'.");
        $this->jwtManager->parse($token); // jwtManager is configured for HS256
    }

    public function testParseExpiredToken(): void
    {
        $this->expectException(ExpiredTokenException::class);
        $this->expectExceptionMessage('Token has expired (exp).');

        // Lifetime of -1 second to make it instantly expired
        $expiredToken = $this->jwtManager->generate(['data' => 'value'], -1);

        // To ensure time has passed for 'exp' to be in the past.
        // A robust way without sleep is to manually craft an expired token if possible,
        // but generate() with negative lifetime is designed for this.
        // If this test is flaky, it might be due to system clock precision or test execution speed.
        // Forcing the time for 'exp' to be in the past.
        $parts = explode('.', $expiredToken);
        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
        $payload['exp'] = time() - 10; // Definitely expired
        $parts[1] = $this->base64UrlEncode(json_encode($payload));

        // Re-sign the modified payload
        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        $signatureInput = "{$parts[0]}.{$parts[1]}";
        $newSignature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, $header['alg']);
        $parts[2] = $this->base64UrlEncode($newSignature);
        $trulyExpiredToken = implode('.', $parts);

        $this->jwtManager->parse($trulyExpiredToken);
    }

    public function testParseTokenBeforeValidTime(): void
    {
        $this->expectException(BeforeValidTokenException::class);
        $this->expectExceptionMessage('Token is not yet valid (nbf).');

        $nbfTimestamp = (new DateTimeImmutable())->modify('+1 hour')->getTimestamp();
        $token = $this->jwtManager->generate(['data' => 'value', 'nbf' => $nbfTimestamp]);
        $this->jwtManager->parse($token);
    }

    public function testParseTokenWithExplicitlySetIatInPast(): void
    {
        $iatTimestamp = (new DateTimeImmutable())->modify('-1 hour')->getTimestamp();
        $token = $this->jwtManager->generate(['data' => 'value', 'iat' => $iatTimestamp]); // iat is overwritten by generate
        $parsed = $this->jwtManager->parse($token);
        $this->assertNotEquals($iatTimestamp, $parsed->iat); // Ensure generate sets its own iat
        $this->assertGreaterThan($iatTimestamp, $parsed->iat);
    }


    public function testParseTokenWithInvalidSignature(): void
    {
        $this->expectException(SignatureInvalidException::class);
        $this->expectExceptionMessage('Token signature verification failed.');

        $token = $this->jwtManager->generate(['data' => 'value']);

        // Attempt to parse with a manager using a different secret
        $anotherManager = new JwtManager(self::ALT_SECRET);
        $anotherManager->parse($token);
    }

    public function testParseTokenWithManipulatedPayload(): void
    {
        $this->expectException(SignatureInvalidException::class);
        $token = $this->jwtManager->generate(['uid' => 1]);
        list($header, $payload, $signature) = explode('.', $token);

        // Decode payload, manipulate it, re-encode
        $decodedPayload = json_decode($this->base64UrlDecode($payload), true);
        $decodedPayload['uid'] = 2; // Change user ID
        $manipulatedPayload = $this->base64UrlEncode(json_encode($decodedPayload));

        $manipulatedToken = "{$header}.{$manipulatedPayload}.{$signature}";
        $this->jwtManager->parse($manipulatedToken);
    }

    public function testParseMalformedTokenIncorrectSegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token format: incorrect number of segments.');
        $this->jwtManager->parse('malformed.token');
    }

    public function testParseMalformedTokenEmptySegment(): void
    {
        $this->expectException(InvalidTokenException::class);
        // This might also lead to Base64Url decoding error depending on which segment is empty
        // and how base64UrlDecode handles empty string.
        // If base64UrlDecode('') returns '', json_decode('') is null.
        // Let's make the signature empty, which is a common manipulation attempt.
        $token = $this->jwtManager->generate(['data' => 'test']);
        $parts = explode('.', $token);
        $malformedToken = "{$parts[0]}.{$parts[1]}."; // Empty signature part
        $this->jwtManager->parse($malformedToken); // parse will try to decode it.
                                                   // Our base64UrlDecode will likely fail or return empty string.
                                                   // If it returns empty, hash_equals will fail.
                                                   // SignatureInvalidException is more likely if header/payload are fine.
                                                   // Let's test for invalid base64 in signature.
        $malformedTokenInvalidBase64Signature = "{$parts[0]}.{$parts[1]}.%%%";
        $this->expectException(InvalidTokenException::class); // due to base64UrlDecode failing for signature
        $this->jwtManager->parse($malformedTokenInvalidBase64Signature);
    }


    public function testParseTokenWithInvalidJsonInPayloadSegment(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token payload: Malformed JSON.');

        $header = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        // Invalid JSON: note the single quotes and unquoted key
        $invalidJsonPayload = $this->base64UrlEncode("{'json': unquoted_string_literal_is_invalid}");

        // Generate a valid signature for a known payload to make the test specific to payload JSON error
        $dummyPayloadForSig = $this->base64UrlEncode(json_encode(['correct' => 'payload']));
        $signatureInput = "{$header}.{$dummyPayloadForSig}";
        $signature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, 'HS256');
        $encodedSignature = $this->base64UrlEncode($signature);

        $malformedToken = "{$header}.{$invalidJsonPayload}.{$encodedSignature}";
        $this->jwtManager->parse($malformedToken);
    }

    public function testParseTokenWithInvalidJsonInHeaderSegment(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token header: Malformed JSON.');

        $invalidJsonHeader = $this->base64UrlEncode("{'alg': 'HS256',, 'typ': 'JWT'}"); // Extra comma
        $payload = $this->base64UrlEncode(json_encode(['data' => 'test']));

        $signatureInput = "{$invalidJsonHeader}.{$payload}"; // Signature won't match anyway, but JSON error comes first
        $signature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, 'HS256'); // This sign might fail if header is used by sign
        $encodedSignature = $this->base64UrlEncode("dummySignature"); // Actual signature does not matter as header parsing fails first

        $malformedToken = "{$invalidJsonHeader}.{$payload}.{$encodedSignature}";
        $this->jwtManager->parse($malformedToken);
    }

    public function testParseTokenWithNonMatchingAlgorithmInHeader(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token algorithm 'HS512' does not match manager's configured algorithm 'HS256'.");

        $headerArray = ['alg' => 'HS512', 'typ' => 'JWT'];
        $payloadArray = ['uid' => 1, 'iat' => time(), 'exp' => time() + 3600, 'nbf' => time()];

        $encodedHeader = $this->base64UrlEncode(json_encode($headerArray));
        $encodedPayload = $this->base64UrlEncode(json_encode($payloadArray));

        // The signature should be generated using the ALGORITHM THE MANAGER IS CONFIGURED WITH (HS256)
        // because the token is *intended* for this manager. The 'alg' in the header is a lie.
        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $signature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, 'HS256');
        $encodedSignature = $this->base64UrlEncode($signature);

        $tokenWithWrongAlgInHeader = "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";

        // This manager is configured for HS256. It will see HS512 in header and reject.
        $this->jwtManager->parse($tokenWithWrongAlgInHeader);
    }

    public function testParseTokenWithUnsupportedAlgorithmInHeader(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Algorithm 'XYZ123' present in token header is not supported by this manager.");

        $headerArray = ['alg' => 'XYZ123', 'typ' => 'JWT']; // Totally unsupported alg
        $payloadArray = ['uid' => 1];

        $encodedHeader = $this->base64UrlEncode(json_encode($headerArray));
        $encodedPayload = $this->base64UrlEncode(json_encode($payloadArray));

        // Signature doesn't matter much as the alg check in header comes first
        $encodedSignature = $this->base64UrlEncode("dummysig");

        $tokenWithUnsupportedAlg = "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";
        $this->jwtManager->parse($tokenWithUnsupportedAlg);
    }


    public function testValidateMethodReturnsTrueForValidToken(): void
    {
        $token = $this->jwtManager->generate(['data' => 'is_valid']);
        $this->assertTrue($this->jwtManager->validate($token));
    }

    public function testValidateMethodReturnsFalseForExpiredToken(): void
    {
        $expiredToken = $this->jwtManager->generate(['data' => 'is_invalid'], -3600); // Expired 1 hour ago
        $this->assertFalse($this->jwtManager->validate($expiredToken));
    }

    public function testValidateMethodReturnsFalseForBadSignatureToken(): void
    {
        $manager1 = new JwtManager('secret1');
        $token = $manager1->generate(['uid' => 123]);

        $manager2 = new JwtManager('secret2'); // Different secret
        $this->assertFalse($manager2->validate($token));
    }

    public function testValidateMethodReturnsFalseForMalformedToken(): void
    {
        $this->assertFalse($this->jwtManager->validate("a.b.c.d")); // Too many segments
        $this->assertFalse($this->jwtManager->validate("a.b"));   // Too few segments
    }

    public function testConstructorWithEmptySecretThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Secret key cannot be empty.');
        new JwtManager('');
    }

    public function testConstructorWithUnsupportedAlgorithmThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported algorithm: FOO123.'); // Message includes the list
        new JwtManager('secret', 'FOO123');
    }

    public function testConstructorWithHS384Algorithm(): void
    {
        $manager = new JwtManager(self::TEST_SECRET, 'HS384');
        $token = $manager->generate(['data' => 'test']);
        $payload = $manager->parse($token);
        $this->assertEquals('test', $payload->data);

        // Check header alg
        list($headerEncoded) = explode('.', $token);
        $header = json_decode($this->base64UrlDecode($headerEncoded), true);
        $this->assertEquals('HS384', $header['alg']);
    }

    public function testConstructorWithHS512Algorithm(): void
    {
        $manager = new JwtManager(self::TEST_SECRET, 'HS512');
        $token = $manager->generate(['data' => 'test']);
        $payload = $manager->parse($token);
        $this->assertEquals('test', $payload->data);

        // Check header alg
        list($headerEncoded) = explode('.', $token);
        $header = json_decode($this->base64UrlDecode($headerEncoded), true);
        $this->assertEquals('HS512', $header['alg']);
    }

    public function testParseHS256TokenWithHS384ManagerFails(): void
    {
        $hs256Token = $this->jwtManager->generate(['data' => 'hs256-data']); // Default manager is HS256

        $hs384Manager = new JwtManager(self::TEST_SECRET, 'HS384');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token algorithm 'HS256' does not match manager's configured algorithm 'HS384'.");
        $hs384Manager->parse($hs256Token);
    }

    public function testParseHS384TokenWithHS512ManagerFails(): void
    {
        $hs384Manager = new JwtManager(self::TEST_SECRET, 'HS384');
        $hs384Token = $hs384Manager->generate(['data' => 'hs384-data']);

        $hs512Manager = new JwtManager(self::TEST_SECRET, 'HS512');

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token algorithm 'HS384' does not match manager's configured algorithm 'HS512'.");
        $hs512Manager->parse($hs384Token);
    }

    public function testParseTokenMissingExpClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token has no expiration (exp) claim.');

        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        $payload = ['uid' => 1, 'iat' => time(), 'nbf' => time()]; // Deliberately missing 'exp'

        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));

        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $signature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, 'HS256');
        $encodedSignature = $this->base64UrlEncode($signature);

        $tokenWithoutExp = "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";

        $this->jwtManager->parse($tokenWithoutExp);
    }

    public function testParseTokenWithNonNumericExpClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid exp claim: Must be a numeric timestamp.');
        $token = $this->generateTokenWithCustomPayloadFields(['exp' => 'not-a-timestamp']);
        $this->jwtManager->parse($token);
    }

    public function testParseTokenWithNonNumericNbfClaim(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid nbf claim: Must be a numeric timestamp.');
        $token = $this->generateTokenWithCustomPayloadFields(['nbf' => 'not-a-timestamp', 'exp' => time() + 3600]);
        $this->jwtManager->parse($token);
    }

    public function testParseTokenMissingAlgInHeader(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Invalid token header: Missing or invalid alg.');
        // Header missing 'alg'
        $header = ['typ' => 'JWT'];
        $payload = ['uid' => 1, 'iat' => time(), 'nbf' => time(), 'exp' => time() + 3600];

        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));

        // Signature doesn't matter as header validation fails first
        $encodedSignature = $this->base64UrlEncode('dummysig');

        $tokenWithoutAlg = "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";
        $this->jwtManager->parse($tokenWithoutAlg);
    }

    public function testBase64UrlDecodeWithInvalidCharacters(): void
    {
        // This test is for the helper method, assuming it might be public or used internally by parse
        // If it's private and parse wraps its exceptions, test through parse.
        // JwtManager::base64UrlDecode is private. So we test through parse with invalid base64 segment.
        $this->expectException(InvalidTokenException::class); // This will be wrapped by parse
        $this->expectExceptionMessage('Base64Url decoding failed.');

        $validHeader = $this->base64UrlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $invalidBase64Payload = "this-is-not-valid-base64-%"; // '%' is not a valid base64url char
        $validSignature = $this->base64UrlEncode("anySignature");

        $token = "{$validHeader}.{$invalidBase64Payload}.{$validSignature}";
        $this->jwtManager->parse($token);
    }


    // Helper to generate a token with specific fields, bypassing some of JwtManager's auto-population
    private function generateTokenWithCustomPayloadFields(array $overridePayloadFields): string
    {
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        // Standard payload fields that JwtManager would add
        $payload = [
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600, // Default expiry
            'uid' => 'test-user'
        ];
        // Override with specified fields
        $payload = array_merge($payload, $overridePayloadFields);

        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        $encodedPayload = $this->base64UrlEncode(json_encode($payload));

        $signatureInput = "{$encodedHeader}.{$encodedPayload}";
        $signature = $this->signUsingJwtManagerInternals($signatureInput, self::TEST_SECRET, 'HS256');
        $encodedSignature = $this->base64UrlEncode($signature);

        return "{$encodedHeader}.{$encodedPayload}.{$encodedSignature}";
    }


    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            // This is a simplified check; JwtManager's internal method might be more robust
            // or throw its own specific exception. For this test helper, RuntimeException is fine.
            throw new RuntimeException("Test helper base64UrlDecode failed for data: {$data}");
        }
        return $decoded;
    }

    private function signUsingJwtManagerInternals(string $data, string $key, string $algorithm): string
    {
        if ($algorithm === 'HS256') {
            return hash_hmac('sha256', $data, $key, true);
        }
        // Extend for other algorithms if JwtManager supports them and tests need them
        throw new InvalidArgumentException("Test helper signUsingJwtManagerInternals does not support algorithm: {$algorithm}");
    }
}
