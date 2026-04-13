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
        // Ensure global helpers (auth_url, auth_url_prefix, auth_user_model) are loaded
        // even if composer dump-autoload hasn't run.
        require_once __DIR__ . '/helpers.php';

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

        // Register Twig namespace "@auth" for shipped auth views
        $view = \ZephyrPHP\View\View::getInstance();
        $view->addNamespace('auth', __DIR__ . '/../views');

        // Expose auth helpers to Twig templates
        $view->addFunction('auth_url', function (string $path = '') {
            return auth_url($path);
        });
        $view->addFunction('auth_url_prefix', function () {
            return auth_url_prefix();
        });

        // Load auth routes
        $routesFile = __DIR__ . '/../routes.php';
        if (file_exists($routesFile)) {
            require $routesFile;
        }
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
