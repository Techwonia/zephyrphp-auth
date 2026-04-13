<?php

declare(strict_types=1);

/**
 * Auth module routes.
 *
 * Auto-loaded by AuthServiceProvider::boot(). URL prefix comes from
 * config('auth.url_prefix') — default "/auth".
 */

use ZephyrPHP\Router\Route;
use ZephyrPHP\Middleware\AuthMiddleware;
use ZephyrPHP\Middleware\GuestMiddleware;
use ZephyrPHP\Auth\Controllers\LoginController;
use ZephyrPHP\Auth\Controllers\PasswordResetController;
use ZephyrPHP\Auth\Controllers\InvitationController;

$prefix = auth_url_prefix();

// Login / logout
Route::get($prefix . '/login', [LoginController::class, 'showLoginForm'], [GuestMiddleware::class]);
Route::post($prefix . '/login', [LoginController::class, 'login'], [GuestMiddleware::class]);
Route::post($prefix . '/logout', [LoginController::class, 'logout'], [AuthMiddleware::class]);

// Password reset
Route::get($prefix . '/forgot-password', [PasswordResetController::class, 'showForgotForm'], [GuestMiddleware::class]);
Route::post($prefix . '/forgot-password', [PasswordResetController::class, 'sendResetLink'], [GuestMiddleware::class]);
Route::get($prefix . '/reset-password', [PasswordResetController::class, 'showResetForm'], [GuestMiddleware::class]);
Route::post($prefix . '/reset-password', [PasswordResetController::class, 'resetPassword'], [GuestMiddleware::class]);

// Invitation acceptance
Route::get($prefix . '/invite/accept', [InvitationController::class, 'showAcceptForm'], [GuestMiddleware::class]);
Route::post($prefix . '/invite/accept', [InvitationController::class, 'accept'], [GuestMiddleware::class]);
