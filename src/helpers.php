<?php

declare(strict_types=1);

use ZephyrPHP\Config\Config;

if (!function_exists('auth_url_prefix')) {
    /**
     * Return the configured URL prefix for auth routes (default "/auth").
     * Sanitized to alphanumerics, hyphens, slashes, underscores.
     */
    function auth_url_prefix(): string
    {
        static $cached;
        if ($cached !== null) {
            return $cached;
        }
        $prefix = Config::get('auth.url_prefix', '/auth');
        $prefix = '/' . trim((string) $prefix, '/');
        if (!preg_match('#^/[A-Za-z0-9/_-]*$#', $prefix)) {
            $prefix = '/auth';
        }
        return $cached = $prefix === '/' ? '' : $prefix;
    }
}

if (!function_exists('auth_url')) {
    /**
     * Build a full URL under the auth prefix. E.g. auth_url('login') → "/auth/login".
     */
    function auth_url(string $path = ''): string
    {
        $path = '/' . ltrim($path, '/');
        return auth_url_prefix() . ($path === '/' ? '' : $path);
    }
}

if (!function_exists('auth_user_model')) {
    /**
     * Resolve the configured User model class, falling back to auto-detection
     * from the host project's composer.json PSR-4 mapping.
     */
    function auth_user_model(): string
    {
        static $cached;
        if ($cached !== null) {
            return $cached;
        }

        $model = Config::get('auth.providers.users.model', '');
        if ($model && class_exists($model)) {
            return $cached = $model;
        }

        $basePath = defined('BASE_PATH') ? BASE_PATH : getcwd();
        $composerFile = $basePath . '/composer.json';
        if (file_exists($composerFile)) {
            $composer = json_decode((string) file_get_contents($composerFile), true);
            $psr4 = $composer['autoload']['psr-4'] ?? [];
            foreach ($psr4 as $namespace => $path) {
                $userFile = $basePath . '/' . rtrim((string) $path, '/') . '/Models/User.php';
                if (file_exists($userFile)) {
                    return $cached = rtrim((string) $namespace, '\\') . '\\Models\\User';
                }
            }
        }

        return $cached = '';
    }
}
