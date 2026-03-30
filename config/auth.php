<?php

/**
 * Authentication Configuration
 *
 * Configure authentication guards, providers, and various auth strategies.
 *
 * Supported Authentication Types:
 * - Session: Traditional cookie-based auth for web apps
 * - JWT: Token-based auth for APIs and SPAs
 * - Basic: HTTP Basic authentication
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
            'model' => '', // Auto-detected from composer.json PSR-4 mapping
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
        'secret' => env('JWT_SECRET'),
        'algorithm' => env('JWT_ALGORITHM', 'HS256'),
        'lifetime' => env('JWT_LIFETIME', 3600),           // Access token: 1 hour
        'refresh_lifetime' => env('JWT_REFRESH', 2592000), // Refresh token: 30 days
        'issuer' => env('JWT_ISSUER', env('APP_URL', '')),
        'audience' => env('JWT_AUDIENCE', env('APP_URL', '')),
        'leeway' => 60, // Clock skew tolerance in seconds
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
