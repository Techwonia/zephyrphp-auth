<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

use ZephyrPHP\Container\Container;
use ZephyrPHP\Config\Config;

class AuthServiceProvider
{
    public function register(Container $container): void
    {
        // Register Auth as singleton
        $container->singleton(Auth::class, function () {
            return new Auth();
        });

        // Register JwtToken
        $container->singleton(JwtToken::class, function () {
            return new JwtToken();
        });

        // Register aliases
        $container->alias('auth', Auth::class);
        $container->alias('jwt', JwtToken::class);
    }

    public function boot(): void
    {
        // Configure Auth from config
        $authConfig = Config::get('auth', []);

        if (!empty($authConfig)) {
            Auth::configure($authConfig);
        }

        // Configure JWT from config
        $jwtConfig = Config::get('auth.jwt', []);

        if (!empty($jwtConfig)) {
            JwtToken::configure($jwtConfig);
        }

        // Register default user provider
        $providerConfig = Config::get('auth.providers.users', []);
        $model = $providerConfig['model'] ?? 'App\\Models\\User';

        Auth::provider('web', new DatabaseUserProvider($model));
        Auth::provider('api', new DatabaseUserProvider($model));
    }
}
