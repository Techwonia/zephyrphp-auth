<?php

/**
 * Authentication Configuration
 *
 * Configure authentication guards, providers, and various auth strategies.
 *
 * Supported Authentication Types:
 * - Session: Traditional cookie-based auth for web apps
 * - JWT: Token-based auth for APIs and SPAs
 * - API Key: Simple key-based auth for external API access
 * - Basic: HTTP Basic authentication
 * - OAuth2: Social login (Google, GitHub, Facebook, etc.)
 * - Magic Link: Passwordless email login
 * - 2FA: Two-factor authentication (TOTP)
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Authentication Defaults
    |--------------------------------------------------------------------------
    */
    'defaults' => [
        'guard' => env('AUTH_GUARD', 'web'),
        'provider' => 'users',
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Guards
    |--------------------------------------------------------------------------
    |
    | Guards define how users are authenticated for each request.
    |
    | Supported drivers: "session", "jwt", "token", "basic"
    |
    */
    'guards' => [
        // Web guard - Session-based authentication for browser requests
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],

        // API guard - JWT token authentication for API requests
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],

        // API Key guard - Simple token for external integrations
        'api_key' => [
            'driver' => 'token',
            'provider' => 'users',
            'input_key' => 'api_key',      // Query parameter name
            'header_key' => 'X-API-Key',   // Header name
            'storage_key' => 'api_key',    // Column in users table
        ],

        // Basic auth guard - HTTP Basic authentication
        'basic' => [
            'driver' => 'basic',
            'provider' => 'users',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | User Providers
    |--------------------------------------------------------------------------
    |
    | Providers define how users are retrieved from storage.
    |
    | Supported drivers: "database"
    |
    */
    'providers' => [
        'users' => [
            'driver' => 'database',
            'model' => 'App\\Models\\User',
            'table' => 'users',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Enabled Authentication Features
    |--------------------------------------------------------------------------
    |
    | Toggle authentication features on/off based on your app needs.
    |
    */
    'features' => [
        'registration' => env('AUTH_REGISTRATION', true),
        'password_reset' => env('AUTH_PASSWORD_RESET', true),
        'email_verification' => env('AUTH_EMAIL_VERIFICATION', false),
        'remember_me' => env('AUTH_REMEMBER_ME', true),
        'two_factor' => env('AUTH_TWO_FACTOR', false),
        'social_login' => env('AUTH_SOCIAL_LOGIN', false),
        'magic_link' => env('AUTH_MAGIC_LINK', false),
        'api_keys' => env('AUTH_API_KEYS', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Authentication Settings
    |--------------------------------------------------------------------------
    */
    'session' => [
        'key' => 'auth_user_id',
        'remember_key' => 'auth_remember_token',
        'remember_duration' => 2592000, // 30 days in seconds
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT (JSON Web Token) Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for stateless token-based authentication.
    |
    */
    'jwt' => [
        'secret' => env('JWT_SECRET', ''),
        'algorithm' => env('JWT_ALGORITHM', 'HS256'),
        'lifetime' => env('JWT_LIFETIME', 3600),           // Access token: 1 hour
        'refresh_lifetime' => env('JWT_REFRESH', 2592000), // Refresh token: 30 days
        'issuer' => env('JWT_ISSUER', env('APP_URL', '')),
        'audience' => env('JWT_AUDIENCE', env('APP_URL', '')),
        'leeway' => 60, // Clock skew tolerance in seconds
    ],

    /*
    |--------------------------------------------------------------------------
    | OAuth2 / Social Login Configuration
    |--------------------------------------------------------------------------
    |
    | Configure OAuth2 providers for social login.
    | Each provider requires client_id, client_secret, and redirect URL.
    |
    */
    'oauth' => [
        'google' => [
            'enabled' => env('OAUTH_GOOGLE_ENABLED', false),
            'client_id' => env('OAUTH_GOOGLE_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_GOOGLE_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_GOOGLE_REDIRECT', '/auth/google/callback'),
            'scopes' => ['email', 'profile'],
        ],

        'github' => [
            'enabled' => env('OAUTH_GITHUB_ENABLED', false),
            'client_id' => env('OAUTH_GITHUB_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_GITHUB_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_GITHUB_REDIRECT', '/auth/github/callback'),
            'scopes' => ['user:email'],
        ],

        'facebook' => [
            'enabled' => env('OAUTH_FACEBOOK_ENABLED', false),
            'client_id' => env('OAUTH_FACEBOOK_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_FACEBOOK_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_FACEBOOK_REDIRECT', '/auth/facebook/callback'),
            'scopes' => ['email'],
        ],

        'twitter' => [
            'enabled' => env('OAUTH_TWITTER_ENABLED', false),
            'client_id' => env('OAUTH_TWITTER_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_TWITTER_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_TWITTER_REDIRECT', '/auth/twitter/callback'),
        ],

        'linkedin' => [
            'enabled' => env('OAUTH_LINKEDIN_ENABLED', false),
            'client_id' => env('OAUTH_LINKEDIN_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_LINKEDIN_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_LINKEDIN_REDIRECT', '/auth/linkedin/callback'),
            'scopes' => ['r_emailaddress', 'r_liteprofile'],
        ],

        'microsoft' => [
            'enabled' => env('OAUTH_MICROSOFT_ENABLED', false),
            'client_id' => env('OAUTH_MICROSOFT_CLIENT_ID', ''),
            'client_secret' => env('OAUTH_MICROSOFT_CLIENT_SECRET', ''),
            'redirect' => env('OAUTH_MICROSOFT_REDIRECT', '/auth/microsoft/callback'),
            'scopes' => ['User.Read'],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Two-Factor Authentication (2FA)
    |--------------------------------------------------------------------------
    |
    | TOTP-based two-factor authentication settings.
    |
    */
    'two_factor' => [
        'issuer' => env('APP_NAME', 'ZephyrPHP'),
        'digits' => 6,
        'period' => 30,  // Seconds
        'algorithm' => 'sha1',
        'window' => 1,   // Allow 1 period before/after for clock drift
        'recovery_codes' => 8,  // Number of recovery codes to generate
    ],

    /*
    |--------------------------------------------------------------------------
    | Magic Link (Passwordless) Authentication
    |--------------------------------------------------------------------------
    */
    'magic_link' => [
        'expire' => 15,    // Minutes until link expires
        'throttle' => 60,  // Seconds between requests
        'table' => 'magic_links',
    ],

    /*
    |--------------------------------------------------------------------------
    | API Key Authentication
    |--------------------------------------------------------------------------
    */
    'api_keys' => [
        'table' => 'api_keys',
        'hash' => true,           // Store hashed keys
        'prefix' => 'zph_',       // Key prefix for identification
        'length' => 32,           // Key length (excluding prefix)
        'rate_limit' => 1000,     // Requests per hour (0 = unlimited)
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Reset Configuration
    |--------------------------------------------------------------------------
    */
    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,      // Minutes
            'throttle' => 60,    // Seconds between requests
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Password Requirements
    |--------------------------------------------------------------------------
    */
    'password' => [
        'min_length' => 8,
        'require_uppercase' => false,
        'require_lowercase' => false,
        'require_numbers' => false,
        'require_symbols' => false,
        'check_pwned' => false,  // Check against haveibeenpwned database
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Protect against brute force attacks.
    |
    */
    'rate_limiting' => [
        'login' => [
            'max_attempts' => 5,
            'decay_minutes' => 1,
        ],
        'password_reset' => [
            'max_attempts' => 3,
            'decay_minutes' => 1,
        ],
        'register' => [
            'max_attempts' => 5,
            'decay_minutes' => 60,
        ],
    ],
];
