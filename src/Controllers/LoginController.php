<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth\Controllers;

use ZephyrPHP\Core\Controllers\Controller;
use ZephyrPHP\Auth\Auth;

class LoginController extends Controller
{
    public function showLoginForm(): string
    {
        return $this->render('@auth/login');
    }

    public function login(): void
    {
        $email = $this->input('email', '');
        $password = $this->input('password', '');
        $remember = $this->boolean('remember');

        $errors = [];

        if (empty($email)) {
            $errors['email'] = 'Email is required.';
        }
        if (empty($password)) {
            $errors['password'] = 'Password is required.';
        }

        if (!empty($errors)) {
            $this->flash('errors', $errors);
            $this->flash('_old_input', ['email' => $email]);
            $this->back();
            return;
        }

        if (Auth::attempt(['email' => $email, 'password' => $password], $remember)) {
            $this->redirectAfterLogin();
            return;
        }

        $this->flash('errors', ['email' => 'These credentials do not match our records.']);
        $this->flash('_old_input', ['email' => $email]);
        $this->back();
    }

    public function logout(): void
    {
        Auth::logout();
        $this->redirect(auth_url('login'));
    }

    /**
     * Post-login redirect. Honors intended URL, falls back to the admin panel.
     */
    private function redirectAfterLogin(): void
    {
        $intended = $this->session->get('url_intended', '/');
        $this->session->remove('url_intended');

        // Guard against open redirect
        if (!str_starts_with($intended, '/') || str_starts_with($intended, '//')) {
            $intended = '/';
        }

        if ($intended && $intended !== '/') {
            $this->redirect($intended);
            return;
        }

        $this->redirect('/' . ltrim($_ENV['ADMIN_PATH'] ?? 'admin', '/'));
    }
}
