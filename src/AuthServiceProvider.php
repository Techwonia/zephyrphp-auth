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
        $model = $providerConfig['model'] ?? null;

        // Auto-detect User model if not configured
        if (!$model) {
            $model = $this->detectUserModel();
        }

        Auth::provider('web', new DatabaseUserProvider($model));
        Auth::provider('api', new DatabaseUserProvider($model));
    }

    /**
     * Auto-detect the User model class by reading composer.json autoload PSR-4 mapping.
     * If the user renamed their namespace (e.g. App → Mysite), this finds the correct class.
     */
    private function detectUserModel(): string
    {
        $basePath = defined('BASE_PATH') ? BASE_PATH : getcwd();
        $composerFile = $basePath . '/composer.json';

        if (file_exists($composerFile)) {
            $composer = json_decode(file_get_contents($composerFile), true);
            $psr4 = $composer['autoload']['psr-4'] ?? [];

            foreach ($psr4 as $namespace => $path) {
                // Check if Models/User.php exists under this namespace
                $userFile = $basePath . '/' . rtrim($path, '/') . '/Models/User.php';
                if (file_exists($userFile)) {
                    return rtrim($namespace, '\\') . '\\Models\\User';
                }
            }
        }

        // No model found via config or auto-detection
        return '';
    }
}
