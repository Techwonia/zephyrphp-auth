<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth\Controllers;

use ZephyrPHP\Core\Controllers\Controller;
use ZephyrPHP\Security\Hash;
use ZephyrPHP\Database\Connection;
use ZephyrPHP\Config\Config;
use ZephyrPHP\Cms\Services\MailService;

class PasswordResetController extends Controller
{
    public function showForgotForm(): string
    {
        return $this->render('@auth/forgot-password');
    }

    public function sendResetLink(): void
    {
        $this->validateCSRF();

        $email = trim($this->input('email', ''));

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->flash('errors', ['email' => 'Please enter a valid email address.']);
            $this->flash('_old_input', ['email' => $email]);
            $this->back();
            return;
        }

        // Rate limit: max 3 requests per minute per email
        $rateLimitKey = 'password_reset:' . md5(strtolower($email));
        if ($this->isRateLimited($rateLimitKey, 3, 60)) {
            $this->flash('success', 'If an account with that email exists, we have sent a password reset link.');
            $this->back();
            return;
        }
        $this->recordAttempt($rateLimitKey);

        // Always show the same success message regardless of whether the email exists
        $this->flash('success', 'If an account with that email exists, we have sent a password reset link.');

        $userClass = auth_user_model();
        $user = $userClass ? $userClass::findOneBy(['email' => strtolower($email)]) : null;

        if ($user) {
            $this->ensureTable();

            $conn = Connection::getInstance()->getConnection();

            $expireMinutes = (int) Config::get('auth.passwords.users.expire', 60);
            $cutoff = (new \DateTime())->modify("-{$expireMinutes} minutes")->format('Y-m-d H:i:s');
            $conn->executeStatement(
                'DELETE FROM password_resets WHERE email = ? AND created_at < ?',
                [strtolower($email), $cutoff]
            );

            $plainToken = Hash::randomToken(32);
            $hashedToken = Hash::make($plainToken);

            $conn->executeStatement(
                'INSERT INTO password_resets (email, token, created_at) VALUES (?, ?, ?)',
                [strtolower($email), $hashedToken, (new \DateTime())->format('Y-m-d H:i:s')]
            );

            $appUrl = rtrim($_ENV['APP_URL'] ?? '', '/');
            $basePath = $_ENV['BASE_PATH'] ?? '';
            $resetUrl = $appUrl . $basePath . auth_url('reset-password')
                . '?token=' . urlencode($plainToken)
                . '&email=' . urlencode(strtolower($email));

            $mail = MailService::getInstance();
            $sent = $mail->sendTemplate('password-reset', $user->getEmail(), [
                'name' => $user->getName(),
                'reset_url' => $resetUrl,
                'expire_minutes' => $expireMinutes,
            ]);

            if (!$sent) {
                $appName = $_ENV['APP_NAME'] ?? 'ZephyrPHP';
                $subject = "Reset Your Password - {$appName}";
                $body = $this->buildResetEmailHtml($user->getName(), $resetUrl, $expireMinutes, $appName);
                $mail->send($user->getEmail(), $subject, $body, $user->getName());
            }
        }

        $this->back();
    }

    public function showResetForm(): string
    {
        $token = $this->query('token', '');
        $email = $this->query('email', '');

        if (empty($token) || empty($email)) {
            $this->flash('error', 'Invalid password reset link.');
            $this->redirect(auth_url('login'));
        }

        return $this->render('@auth/reset-password', [
            'token' => $token,
            'email' => $email,
        ]);
    }

    public function resetPassword(): void
    {
        $this->validateCSRF();

        $token = $this->input('token', '');
        $email = trim($this->input('email', ''));
        $password = $this->input('password', '');
        $passwordConfirmation = $this->input('password_confirmation', '');

        $errors = [];

        if (empty($token) || empty($email)) {
            $errors['token'] = 'Invalid password reset link.';
        }

        if (empty($password)) {
            $errors['password'] = 'Password is required.';
        } elseif (strlen($password) < 8) {
            $errors['password'] = 'Password must be at least 8 characters.';
        } elseif (!preg_match('/[A-Z]/', $password)) {
            $errors['password'] = 'Password must contain at least one uppercase letter.';
        } elseif (!preg_match('/[a-z]/', $password)) {
            $errors['password'] = 'Password must contain at least one lowercase letter.';
        } elseif (!preg_match('/[0-9]/', $password)) {
            $errors['password'] = 'Password must contain at least one number.';
        }

        if ($password !== $passwordConfirmation) {
            $errors['password_confirmation'] = 'Passwords do not match.';
        }

        $resetUrl = auth_url('reset-password') . '?token=' . urlencode($token) . '&email=' . urlencode($email);

        if (!empty($errors)) {
            $this->flash('errors', $errors);
            $this->redirect($resetUrl);
            return;
        }

        $this->ensureTable();

        $conn = Connection::getInstance()->getConnection();
        $expireMinutes = (int) Config::get('auth.passwords.users.expire', 60);

        $cutoff = (new \DateTime())->modify("-{$expireMinutes} minutes")->format('Y-m-d H:i:s');
        $rows = $conn->fetchAllAssociative(
            'SELECT token, created_at FROM password_resets WHERE email = ? AND created_at >= ?',
            [strtolower($email), $cutoff]
        );

        $validToken = false;
        foreach ($rows as $row) {
            if (Hash::check($token, $row['token'])) {
                $validToken = true;
                break;
            }
        }

        if (!$validToken) {
            $this->flash('errors', ['token' => 'This password reset link is invalid or has expired.']);
            $this->redirect($resetUrl);
            return;
        }

        $userClass = auth_user_model();
        $user = $userClass ? $userClass::findOneBy(['email' => strtolower($email)]) : null;
        if (!$user) {
            $this->flash('errors', ['token' => 'This password reset link is invalid or has expired.']);
            $this->redirect($resetUrl);
            return;
        }

        $user->setPassword(Hash::make($password));
        $em = \ZephyrPHP\Database\EntityManager::getInstance();
        $em->persist($user);
        $em->flush();

        $conn->executeStatement('DELETE FROM password_resets WHERE email = ?', [strtolower($email)]);

        $this->flash('success', 'Your password has been reset. You can now sign in.');
        $this->redirect(auth_url('login'));
    }

    private function ensureTable(): void
    {
        $conn = Connection::getInstance()->getConnection();
        $sm = $conn->createSchemaManager();
        if (!$sm->tablesExist(['password_resets'])) {
            $conn->executeStatement('CREATE TABLE password_resets (
                email VARCHAR(255) NOT NULL,
                token VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL,
                INDEX idx_email (email)
            )');
        }
    }

    private function getStorageDir(string $subdir): string
    {
        $dir = (defined('BASE_PATH') ? BASE_PATH : dirname(__DIR__, 4)) . '/storage/' . $subdir;
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        return $dir;
    }

    private function getRateLimitFile(string $key): string
    {
        return $this->getStorageDir('rate_limits') . '/' . hash('sha256', $key) . '.json';
    }

    private function isRateLimited(string $key, int $maxAttempts, int $decaySeconds): bool
    {
        $file = $this->getRateLimitFile($key);
        if (!file_exists($file)) {
            return false;
        }

        $cutoff = time() - $decaySeconds;

        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return false;
        }
        flock($fp, LOCK_EX);

        $content = stream_get_contents($fp);
        $data = @json_decode($content ?: '[]', true);
        if (!is_array($data)) {
            $data = [];
        }

        $attempts = array_filter($data, fn(int $timestamp) => $timestamp >= $cutoff);

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode(array_values($attempts)));
        flock($fp, LOCK_UN);
        fclose($fp);

        return count($attempts) >= $maxAttempts;
    }

    private function recordAttempt(string $key): void
    {
        $file = $this->getRateLimitFile($key);

        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return;
        }
        flock($fp, LOCK_EX);

        $content = stream_get_contents($fp);
        $attempts = @json_decode($content ?: '[]', true);
        if (!is_array($attempts)) {
            $attempts = [];
        }

        $attempts[] = time();

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($attempts));
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    private function buildResetEmailHtml(string $name, string $resetUrl, int $expireMinutes, string $appName): string
    {
        $escapedName = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        $escapedUrl = htmlspecialchars($resetUrl, ENT_QUOTES, 'UTF-8');
        $escapedAppName = htmlspecialchars($appName, ENT_QUOTES, 'UTF-8');

        return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f4f4f5; padding: 40px 20px;">
    <div style="max-width: 480px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 32px; border: 1px solid #e4e4e7;">
        <h2 style="margin: 0 0 16px; font-size: 1.25rem; color: #18181b;">Reset Your Password</h2>
        <p style="color: #52525b; line-height: 1.6; margin: 0 0 24px;">
            Hi {$escapedName}, you requested a password reset for your {$escapedAppName} account.
            Click the button below to choose a new password. This link expires in {$expireMinutes} minutes.
        </p>
        <a href="{$escapedUrl}" style="display: inline-block; padding: 12px 24px; background: #06b6d4; color: #000; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 0.9rem;">Reset Password</a>
        <p style="color: #a1a1aa; font-size: 0.8rem; margin: 24px 0 0; line-height: 1.5;">
            If you did not request this reset, you can safely ignore this email.<br>
            If the button doesn't work, copy and paste this URL into your browser:<br>
            <span style="color: #52525b; word-break: break-all;">{$escapedUrl}</span>
        </p>
    </div>
</body>
</html>
HTML;
    }
}
