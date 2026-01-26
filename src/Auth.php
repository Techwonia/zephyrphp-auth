<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

use ZephyrPHP\Security\Hash;
use ZephyrPHP\Session\Session;

/**
 * Authentication Manager
 *
 * Provides user authentication with multiple guard support.
 * Handles session-based and token-based authentication.
 *
 * Usage:
 *   // Attempt login
 *   if (Auth::attempt(['email' => $email, 'password' => $password])) { ... }
 *
 *   // Check if authenticated
 *   if (Auth::check()) { ... }
 *
 *   // Get current user
 *   $user = Auth::user();
 *
 *   // Logout
 *   Auth::logout();
 */
class Auth
{
    /** @var Auth|null Singleton instance */
    private static ?Auth $instance = null;

    /** @var AuthenticatableInterface|null Current authenticated user */
    private static ?AuthenticatableInterface $user = null;

    /** @var string Current guard name */
    private static string $currentGuard = 'web';

    /** @var array<string, GuardInterface> Registered guards */
    private static array $guards = [];

    /** @var array<string, UserProviderInterface> Registered user providers */
    private static array $providers = [];

    /** @var bool Whether user has been resolved */
    private static bool $resolved = false;

    /** @var array Configuration */
    private static array $config = [
        'session_key' => 'auth_user_id',
        'remember_key' => 'auth_remember_token',
        'remember_duration' => 2592000, // 30 days
    ];

    /**
     * Attempt to authenticate a user
     *
     * @param array $credentials User credentials (email/username + password)
     * @param bool $remember Whether to remember the user
     * @return bool True if authentication succeeds
     */
    public static function attempt(array $credentials, bool $remember = false): bool
    {
        $provider = self::getProvider();

        // Extract password from credentials
        $password = $credentials['password'] ?? '';
        unset($credentials['password']);

        // Find user by credentials (excluding password)
        $user = $provider->retrieveByCredentials($credentials);

        if ($user === null) {
            return false;
        }

        // Validate password
        if (!$provider->validateCredentials($user, ['password' => $password])) {
            return false;
        }

        // Log the user in
        self::login($user, $remember);

        return true;
    }

    /**
     * Log a user in
     *
     * @param AuthenticatableInterface $user The user to authenticate
     * @param bool $remember Whether to remember the user
     */
    public static function login(AuthenticatableInterface $user, bool $remember = false): void
    {
        self::$user = $user;
        self::$resolved = true;

        // Store in session
        $session = Session::getInstance();
        $session->set(self::$config['session_key'], $user->getAuthIdentifier());

        // Regenerate session ID to prevent session fixation
        $session->regenerate();

        // Set remember token if requested
        if ($remember) {
            self::setRememberToken($user);
        }

        // Fire login event (if event system exists)
        self::fireEvent('login', $user);
    }

    /**
     * Log a user in by ID
     *
     * @param mixed $id User identifier
     * @param bool $remember Whether to remember the user
     * @return bool True if successful
     */
    public static function loginUsingId($id, bool $remember = false): bool
    {
        $user = self::getProvider()->retrieveById($id);

        if ($user === null) {
            return false;
        }

        self::login($user, $remember);
        return true;
    }

    /**
     * Log the user out
     */
    public static function logout(): void
    {
        $user = self::user();

        if ($user !== null) {
            // Clear remember token
            self::clearRememberToken($user);

            // Fire logout event
            self::fireEvent('logout', $user);
        }

        // Clear session
        $session = Session::getInstance();
        $session->forget(self::$config['session_key']);
        $session->regenerate();

        // Clear state
        self::$user = null;
        self::$resolved = false;
    }

    /**
     * Check if user is authenticated
     */
    public static function check(): bool
    {
        return self::user() !== null;
    }

    /**
     * Check if user is a guest (not authenticated)
     */
    public static function guest(): bool
    {
        return !self::check();
    }

    /**
     * Get the currently authenticated user
     */
    public static function user(): ?AuthenticatableInterface
    {
        if (self::$resolved) {
            return self::$user;
        }

        self::$resolved = true;

        // Try to resolve from session
        $session = Session::getInstance();
        $id = $session->get(self::$config['session_key']);

        if ($id !== null) {
            self::$user = self::getProvider()->retrieveById($id);
            return self::$user;
        }

        // Try to resolve from remember token
        $user = self::resolveFromRememberToken();
        if ($user !== null) {
            self::login($user, true);
            return self::$user;
        }

        return null;
    }

    /**
     * Get the authenticated user's ID
     *
     * @return mixed|null User ID or null
     */
    public static function id()
    {
        $user = self::user();
        return $user?->getAuthIdentifier();
    }

    /**
     * Validate credentials without logging in
     *
     * @param array $credentials User credentials
     * @return bool True if credentials are valid
     */
    public static function validate(array $credentials): bool
    {
        $provider = self::getProvider();

        $password = $credentials['password'] ?? '';
        unset($credentials['password']);

        $user = $provider->retrieveByCredentials($credentials);

        if ($user === null) {
            return false;
        }

        return $provider->validateCredentials($user, ['password' => $password]);
    }

    /**
     * Set the currently authenticated user
     *
     * @param AuthenticatableInterface $user The user
     */
    public static function setUser(AuthenticatableInterface $user): void
    {
        self::$user = $user;
        self::$resolved = true;
    }

    /**
     * Determine if the user has been authenticated once (for this request only)
     *
     * @param array $credentials User credentials
     * @return bool True if authenticated for this request
     */
    public static function once(array $credentials): bool
    {
        if (self::validate($credentials)) {
            $provider = self::getProvider();
            $password = $credentials['password'] ?? '';
            unset($credentials['password']);

            $user = $provider->retrieveByCredentials($credentials);

            if ($user !== null) {
                self::setUser($user);
                return true;
            }
        }

        return false;
    }

    /**
     * Log a user in for a single request without sessions
     *
     * @param AuthenticatableInterface $user The user
     */
    public static function onceUsingId($id): bool
    {
        $user = self::getProvider()->retrieveById($id);

        if ($user === null) {
            return false;
        }

        self::setUser($user);
        return true;
    }

    /**
     * Register a user provider
     *
     * @param string $name Provider name
     * @param UserProviderInterface $provider The provider
     */
    public static function provider(string $name, UserProviderInterface $provider): void
    {
        self::$providers[$name] = $provider;
    }

    /**
     * Register a guard
     *
     * @param string $name Guard name
     * @param GuardInterface $guard The guard
     */
    public static function guard(string $name, GuardInterface $guard): void
    {
        self::$guards[$name] = $guard;
    }

    /**
     * Use a specific guard
     *
     * @param string $name Guard name
     * @return static
     */
    public static function useGuard(string $name): void
    {
        self::$currentGuard = $name;
        self::$resolved = false;
        self::$user = null;
    }

    /**
     * Get the current guard name
     */
    public static function getGuardName(): string
    {
        return self::$currentGuard;
    }

    /**
     * Set configuration options
     */
    public static function configure(array $config): void
    {
        self::$config = array_merge(self::$config, $config);
    }

    /**
     * Get current provider
     */
    private static function getProvider(): UserProviderInterface
    {
        $providerName = self::$currentGuard;

        if (!isset(self::$providers[$providerName])) {
            // Return default database provider if none registered
            if (!isset(self::$providers['default'])) {
                self::$providers['default'] = new DatabaseUserProvider();
            }
            return self::$providers['default'];
        }

        return self::$providers[$providerName];
    }

    /**
     * Set remember token for user
     */
    private static function setRememberToken(AuthenticatableInterface $user): void
    {
        $token = Hash::randomToken(60);

        // Store token in user (they should save it)
        $user->setRememberToken($token);

        // Set cookie
        $expires = time() + self::$config['remember_duration'];
        $secure = ($_ENV['SESSION_SECURE'] ?? false) || self::isHttps();

        setcookie(
            self::$config['remember_key'],
            $user->getAuthIdentifier() . '|' . $token,
            [
                'expires' => $expires,
                'path' => '/',
                'secure' => $secure,
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
    }

    /**
     * Clear remember token
     */
    private static function clearRememberToken(AuthenticatableInterface $user): void
    {
        $user->setRememberToken('');

        // Clear cookie
        setcookie(
            self::$config['remember_key'],
            '',
            [
                'expires' => time() - 3600,
                'path' => '/',
                'httponly' => true,
                'samesite' => 'Lax',
            ]
        );
    }

    /**
     * Resolve user from remember token cookie
     */
    private static function resolveFromRememberToken(): ?AuthenticatableInterface
    {
        $cookie = $_COOKIE[self::$config['remember_key']] ?? null;

        if ($cookie === null) {
            return null;
        }

        $parts = explode('|', $cookie, 2);
        if (count($parts) !== 2) {
            return null;
        }

        [$id, $token] = $parts;

        $user = self::getProvider()->retrieveByToken($id, $token);

        return $user;
    }

    /**
     * Check if connection is HTTPS
     */
    private static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['SERVER_PORT'] ?? 80) == 443
            || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }

    /**
     * Fire an authentication event
     */
    private static function fireEvent(string $event, AuthenticatableInterface $user): void
    {
        // Event system integration point
        // Can be extended to dispatch events
    }

    /**
     * Reset auth state (for testing)
     */
    public static function reset(): void
    {
        self::$user = null;
        self::$resolved = false;
        self::$currentGuard = 'web';
    }
}
