<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

use ZephyrPHP\Security\Hash;

/**
 * JWT Token Manager
 *
 * Provides JSON Web Token (JWT) generation and validation for API authentication.
 * Uses HMAC-SHA256 for signing (HS256) - no external dependencies required.
 *
 * For RS256 (RSA), consider using a dedicated JWT library like firebase/php-jwt.
 *
 * Usage:
 *   // Generate a token
 *   $token = JwtToken::generate(['user_id' => 123]);
 *
 *   // Validate and decode
 *   $payload = JwtToken::validate($token);
 *
 *   // Refresh a token
 *   $newToken = JwtToken::refresh($oldToken);
 */
class JwtToken
{
    /** @var string The signing secret */
    private static string $secret = '';

    /** @var int Default token lifetime in seconds (1 hour) */
    private static int $lifetime = 3600;

    /** @var int Refresh token lifetime in seconds (30 days) */
    private static int $refreshLifetime = 2592000;

    /** @var string Token issuer */
    private static string $issuer = '';

    /** @var string Token audience */
    private static string $audience = '';

    /** @var array In-memory token blacklist (jti => true) */
    private static array $blacklist = [];

    /** @var object|null External blacklist store (cache/store interface) */
    private static ?object $blacklistStore = null;

    /** @var string Algorithm */
    private const ALGORITHM = 'HS256';

    /**
     * Generate a JWT token
     *
     * @param array $payload Custom payload data
     * @param int|null $expiration Custom expiration time (timestamp)
     * @return string The JWT token
     */
    public static function generate(array $payload = [], ?int $expiration = null): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => self::ALGORITHM,
        ];

        $now = time();
        $exp = $expiration ?? ($now + self::$lifetime);

        $claims = [
            'iat' => $now,           // Issued at
            'nbf' => $now,           // Not before
            'exp' => $exp,           // Expiration
            'jti' => self::generateJti(), // JWT ID (unique identifier)
        ];

        // Add optional claims
        if (!empty(self::$issuer)) {
            $claims['iss'] = self::$issuer;
        }

        if (!empty(self::$audience)) {
            $claims['aud'] = self::$audience;
        }

        // Merge custom payload
        $claims = array_merge($claims, $payload);

        // Encode header and payload
        $headerEncoded = self::base64UrlEncode(json_encode($header));
        $payloadEncoded = self::base64UrlEncode(json_encode($claims));

        // Create signature
        $signature = self::sign("{$headerEncoded}.{$payloadEncoded}");
        $signatureEncoded = self::base64UrlEncode($signature);

        return "{$headerEncoded}.{$payloadEncoded}.{$signatureEncoded}";
    }

    /**
     * Validate and decode a JWT token
     *
     * @param string $token The JWT token
     * @return array|null The payload if valid, null otherwise
     */
    public static function validate(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

        // Verify signature
        $expectedSignature = self::sign("{$headerEncoded}.{$payloadEncoded}");
        $actualSignature = self::base64UrlDecode($signatureEncoded);

        if (!hash_equals($expectedSignature, $actualSignature)) {
            return null;
        }

        // Decode header
        $header = json_decode(self::base64UrlDecode($headerEncoded), true);
        if ($header === null || ($header['alg'] ?? '') !== self::ALGORITHM) {
            return null;
        }

        // Decode payload
        $payload = json_decode(self::base64UrlDecode($payloadEncoded), true);
        if ($payload === null) {
            return null;
        }

        // Validate claims
        $now = time();
        $leeway = min((int) ($_ENV['JWT_LEEWAY'] ?? 60), 300);

        // Check expiration (with leeway)
        if (isset($payload['exp']) && $payload['exp'] < ($now - $leeway)) {
            return null;
        }

        // Check not before (with leeway)
        if (isset($payload['nbf']) && $payload['nbf'] > ($now + $leeway)) {
            return null;
        }

        // Check issuer
        if (!empty(self::$issuer) && ($payload['iss'] ?? '') !== self::$issuer) {
            return null;
        }

        // Check audience
        if (!empty(self::$audience)) {
            $aud = $payload['aud'] ?? '';
            if (is_array($aud)) {
                if (!in_array(self::$audience, $aud)) {
                    return null;
                }
            } elseif ($aud !== self::$audience) {
                return null;
            }
        }

        // Check if token has been revoked
        if (isset($payload['jti']) && self::isRevoked($payload['jti'])) {
            return null;
        }

        return $payload;
    }

    /**
     * Check if a token is valid
     *
     * @param string $token The JWT token
     * @return bool True if valid
     */
    public static function isValid(string $token): bool
    {
        return self::validate($token) !== null;
    }

    /**
     * Get payload without signature verification
     *
     * WARNING: This returns unverified data. Never trust the output
     * for authentication or authorization decisions.
     *
     * @param string $token The JWT token
     * @return array|null The payload (unverified!)
     */
    private static function decodeWithoutVerification(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        return json_decode(self::base64UrlDecode($parts[1]), true);
    }

    /**
     * Refresh a token (generate new token with same payload)
     *
     * @param string $token The old token
     * @param int|null $expiration New expiration time
     * @return string|null The new token or null if old token is invalid
     */
    public static function refresh(string $token, ?int $expiration = null): ?string
    {
        $payload = self::validate($token);

        if ($payload === null) {
            return null;
        }

        // Only refresh tokens can be used for refreshing
        if (($payload['type'] ?? '') !== 'refresh') {
            return null;
        }

        // Remove standard claims (they'll be regenerated)
        unset($payload['iat'], $payload['nbf'], $payload['exp'], $payload['jti']);

        return self::generate($payload, $expiration);
    }

    /**
     * Generate a refresh token (longer-lived, for getting new access tokens)
     *
     * @param array $payload Custom payload
     * @return string The refresh token
     */
    public static function generateRefreshToken(array $payload = []): string
    {
        $payload['type'] = 'refresh';
        return self::generate($payload, time() + self::$refreshLifetime);
    }

    /**
     * Check if token is a refresh token
     *
     * @param string $token The token
     * @return bool True if it's a refresh token
     */
    public static function isRefreshToken(string $token): bool
    {
        $payload = self::validate($token);
        return $payload !== null && ($payload['type'] ?? '') === 'refresh';
    }

    /**
     * Get time until token expires
     *
     * @param string $token The token
     * @return int Seconds until expiration (0 if expired or invalid)
     */
    public static function expiresIn(string $token): int
    {
        $payload = self::validate($token);

        if ($payload === null || !isset($payload['exp'])) {
            return 0;
        }

        return max(0, $payload['exp'] - time());
    }

    /**
     * Extract user from token
     *
     * @param string $token The token
     * @return AuthenticatableInterface|null The user
     */
    public static function user(string $token): ?AuthenticatableInterface
    {
        $payload = self::validate($token);

        if ($payload === null) {
            return null;
        }

        $userId = $payload['sub'] ?? $payload['user_id'] ?? null;

        if ($userId === null) {
            return null;
        }

        // Use Auth provider to get user
        return Auth::onceUsingId($userId) ? Auth::user() : null;
    }

    /**
     * Generate token for a user
     *
     * @param AuthenticatableInterface $user The user
     * @param array $additionalClaims Additional payload claims
     * @return string The token
     */
    public static function forUser(AuthenticatableInterface $user, array $additionalClaims = []): string
    {
        $payload = array_merge([
            'sub' => $user->getAuthIdentifier(),
        ], $additionalClaims);

        return self::generate($payload);
    }

    /**
     * Set the signing secret
     *
     * @param string $secret The secret key
     */
    public static function setSecret(string $secret): void
    {
        self::$secret = $secret;
    }

    /**
     * Set the token lifetime
     *
     * @param int $seconds Lifetime in seconds
     */
    public static function setLifetime(int $seconds): void
    {
        self::$lifetime = $seconds;
    }

    /**
     * Set the refresh token lifetime
     *
     * @param int $seconds Lifetime in seconds
     */
    public static function setRefreshLifetime(int $seconds): void
    {
        self::$refreshLifetime = $seconds;
    }

    /**
     * Set the token issuer (iss claim)
     *
     * @param string $issuer The issuer
     */
    public static function setIssuer(string $issuer): void
    {
        self::$issuer = $issuer;
    }

    /**
     * Set the token audience (aud claim)
     *
     * @param string $audience The audience
     */
    public static function setAudience(string $audience): void
    {
        self::$audience = $audience;
    }

    /**
     * Configure from array
     */
    public static function configure(array $config): void
    {
        if (isset($config['secret'])) {
            self::setSecret($config['secret']);
        }
        if (isset($config['lifetime'])) {
            self::setLifetime($config['lifetime']);
        }
        if (isset($config['refresh_lifetime'])) {
            self::setRefreshLifetime($config['refresh_lifetime']);
        }
        if (isset($config['issuer'])) {
            self::setIssuer($config['issuer']);
        }
        if (isset($config['audience'])) {
            self::setAudience($config['audience']);
        }
    }

    /**
     * Create HMAC signature
     */
    private static function sign(string $data): string
    {
        $secret = self::getSecret();
        return hash_hmac('sha256', $data, $secret, true);
    }

    /**
     * Get the signing secret
     */
    private static function getSecret(): string
    {
        $secret = self::$secret ?: ($_ENV['JWT_SECRET'] ?? '');

        if (empty($secret)) {
            throw new \RuntimeException('JWT_SECRET must be configured.');
        }

        return $secret;
    }

    /**
     * Generate unique JWT ID
     */
    private static function generateJti(): string
    {
        return Hash::randomUrlSafeToken(16);
    }

    /**
     * Base64 URL encode
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Base64 URL decode
     */
    private static function base64UrlDecode(string $data): string
    {
        $padding = 4 - (strlen($data) % 4);
        if ($padding !== 4) {
            $data .= str_repeat('=', $padding);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }

    /**
     * Set an external blacklist store (cache/store interface)
     *
     * The store must implement `set(string $key, mixed $value, int $ttl): void`
     * and `has(string $key): bool` methods.
     *
     * @param object $store A cache/store object
     */
    public static function setBlacklistStore(object $store): void
    {
        self::$blacklistStore = $store;
    }

    /**
     * Revoke a token by adding its jti to the blacklist
     *
     * @param string $token The JWT token to revoke
     */
    public static function revoke(string $token): void
    {
        $payload = self::validate($token);

        if ($payload === null || !isset($payload['jti'])) {
            return;
        }

        $jti = $payload['jti'];
        $exp = $payload['exp'] ?? (time() + 86400);
        self::$blacklist[$jti] = true;

        // Store in external store if available
        if (self::$blacklistStore !== null && method_exists(self::$blacklistStore, 'set')) {
            $ttl = max(0, $exp - time());
            self::$blacklistStore->set('jwt_blacklist:' . $jti, true, $ttl);
        } else {
            // File-based persistence as default
            self::fileBlacklistAdd($jti, $exp);
        }
    }

    /**
     * Check if a token jti has been revoked
     *
     * @param string $jti The JWT ID
     * @return bool True if the token is revoked
     */
    private static function isRevoked(string $jti): bool
    {
        if (isset(self::$blacklist[$jti])) {
            return true;
        }

        if (self::$blacklistStore !== null && method_exists(self::$blacklistStore, 'has')) {
            return self::$blacklistStore->has('jwt_blacklist:' . $jti);
        }

        // File-based fallback
        return self::fileBlacklistHas($jti);
    }

    /**
     * Get the file path for the JWT blacklist
     */
    private static function getBlacklistFile(): string
    {
        $dir = dirname(__DIR__, 2) . '/storage/jwt_blacklist';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        return $dir . '/blacklist.json';
    }

    /**
     * Add a JTI to the file-based blacklist
     */
    private static function fileBlacklistAdd(string $jti, int $exp): void
    {
        $file = self::getBlacklistFile();
        $entries = self::fileBlacklistLoad($file);
        $entries[$jti] = $exp;
        @file_put_contents($file, json_encode($entries), LOCK_EX);
    }

    /**
     * Check if a JTI exists in the file-based blacklist
     */
    private static function fileBlacklistHas(string $jti): bool
    {
        $file = self::getBlacklistFile();
        if (!file_exists($file)) {
            return false;
        }
        $entries = self::fileBlacklistLoad($file);
        return isset($entries[$jti]) && $entries[$jti] >= time();
    }

    /**
     * Load and prune expired entries from the blacklist file
     */
    private static function fileBlacklistLoad(string $file): array
    {
        if (!file_exists($file)) {
            return [];
        }

        $data = @json_decode((string) @file_get_contents($file), true);
        if (!is_array($data)) {
            return [];
        }

        // Prune expired entries
        $now = time();
        return array_filter($data, fn(int $exp) => $exp >= $now);
    }

    /**
     * Reset state (for testing)
     */
    public static function reset(): void
    {
        self::$secret = '';
        self::$lifetime = 3600;
        self::$refreshLifetime = 2592000;
        self::$issuer = '';
        self::$audience = '';
        self::$blacklist = [];
        self::$blacklistStore = null;
    }
}
