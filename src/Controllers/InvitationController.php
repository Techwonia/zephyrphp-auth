<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth\Controllers;

use ZephyrPHP\Core\Controllers\Controller;
use ZephyrPHP\Auth\Auth;
use ZephyrPHP\Security\Hash;
use ZephyrPHP\Cms\Models\Invitation;

class InvitationController extends Controller
{
    public function showAcceptForm(): string
    {
        $token = $this->query('token', '');
        $email = $this->query('email', '');

        if (empty($token) || empty($email)) {
            $this->flash('error', 'Invalid invitation link.');
            $this->redirect(auth_url('login'));
            return '';
        }

        $invitation = $this->findValidInvitation($email, $token);
        if (!$invitation) {
            $this->flash('error', 'This invitation link is invalid or has expired.');
            $this->redirect(auth_url('login'));
            return '';
        }

        return $this->render('@auth/accept-invite', [
            'token' => $token,
            'email' => $email,
        ]);
    }

    public function accept(): void
    {
        $this->validateCSRF();

        $token = $this->input('token', '');
        $email = strtolower(trim($this->input('email', '')));
        $name = trim($this->input('name', ''));
        $password = $this->input('password', '');
        $passwordConfirmation = $this->input('password_confirmation', '');

        $errors = [];

        if (empty($token) || empty($email)) {
            $errors['token'] = 'Invalid invitation link.';
        }

        if (empty($name)) {
            $errors['name'] = 'Name is required.';
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

        if (!empty($errors)) {
            $this->flash('errors', $errors);
            $this->flash('_old_input', ['name' => $name, 'email' => $email]);
            $this->redirect(auth_url('invite/accept') . '?token=' . urlencode($token) . '&email=' . urlencode($email));
            return;
        }

        $invitation = $this->findValidInvitation($email, $token);
        if (!$invitation) {
            $this->flash('error', 'This invitation link is invalid or has expired.');
            $this->redirect(auth_url('login'));
            return;
        }

        $userClass = auth_user_model();
        if (!$userClass) {
            $this->flash('error', 'User model not configured.');
            $this->redirect(auth_url('login'));
            return;
        }

        $existing = $userClass::findOneBy(['email' => $email]);
        if ($existing) {
            $this->flash('error', 'An account with this email already exists. Please sign in instead.');
            $this->redirect(auth_url('login'));
            return;
        }

        $user = new $userClass();
        $user->setName($name);
        $user->setEmail($email);
        $user->setPassword(Hash::make($password));
        $user->save();

        if ($invitation->getRoleId()) {
            $roleClass = $this->detectRoleModel();
            if ($roleClass) {
                $role = $roleClass::find($invitation->getRoleId());
                if ($role) {
                    $user->assignRole($role);
                    $user->save();
                }
            }
        }

        $invitation->setAcceptedAt(new \DateTime());
        $invitation->save();

        Auth::loginUsingId($user->getId());

        $adminPath = '/' . ltrim($_ENV['ADMIN_PATH'] ?? 'admin', '/');
        $this->redirect($adminPath);
    }

    private function findValidInvitation(string $email, string $plainToken): ?Invitation
    {
        $invitations = Invitation::findBy([
            'email' => strtolower($email),
            'acceptedAt' => null,
        ]);

        foreach ($invitations as $invitation) {
            if ($invitation->isExpired()) {
                continue;
            }
            if (Hash::check($plainToken, $invitation->getToken())) {
                return $invitation;
            }
        }

        return null;
    }

    private function detectRoleModel(): ?string
    {
        $userClass = auth_user_model();
        if (!$userClass) {
            return null;
        }
        // Derive Role class from User namespace: App\Models\User → App\Models\Role
        $parts = explode('\\', $userClass);
        array_pop($parts);
        $roleClass = implode('\\', $parts) . '\\Role';
        return class_exists($roleClass) ? $roleClass : null;
    }
}
