<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

use ZephyrPHP\Security\Hash;

/**
 * Database User Provider
 *
 * Retrieves users from a database using a model class.
 * Configure with your User model class.
 */
class DatabaseUserProvider implements UserProviderInterface
{
    /** @var string The User model class */
    private string $model;

    /** @var string The table name (fallback if no model) */
    private string $table;

    /**
     * Create a new database user provider
     *
     * @param string $model The User model class (must implement AuthenticatableInterface)
     * @param string $table The table name (fallback)
     */
    public function __construct(string $model = 'App\\Models\\User', string $table = 'users')
    {
        $this->model = $model;
        $this->table = $table;
    }

    /**
     * Retrieve a user by their unique identifier
     */
    public function retrieveById($identifier): ?AuthenticatableInterface
    {
        if (!class_exists($this->model)) {
            return null;
        }

        $model = $this->model;

        // Try static find method first (for ORM models)
        if (method_exists($model, 'find')) {
            $user = $model::find($identifier);
            return $user instanceof AuthenticatableInterface ? $user : null;
        }

        // Fallback to findById
        if (method_exists($model, 'findById')) {
            $user = $model::findById($identifier);
            return $user instanceof AuthenticatableInterface ? $user : null;
        }

        return null;
    }

    /**
     * Retrieve a user by their unique identifier and remember token
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface
    {
        $user = $this->retrieveById($identifier);

        if ($user === null) {
            return null;
        }

        $rememberToken = $user->getRememberToken();

        if (empty($rememberToken) || empty($token)) {
            return null;
        }

        // Use timing-safe comparison
        if (!Hash::equals($rememberToken, $token)) {
            return null;
        }

        return $user;
    }

    /**
     * Update the remember token for the given user
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);

        // Save the user if they have a save method
        if (method_exists($user, 'save')) {
            $user->save();
        }
    }

    /**
     * Retrieve a user by the given credentials
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface
    {
        if (empty($credentials)) {
            return null;
        }

        if (!class_exists($this->model)) {
            return null;
        }

        $model = $this->model;

        // Try using query builder if available
        if (method_exists($model, 'query')) {
            $query = $model::query();

            foreach ($credentials as $key => $value) {
                // Skip password - it's validated separately
                if ($key === 'password') {
                    continue;
                }

                $query->where($key, '=', $value);
            }

            $user = $query->first();
            return $user instanceof AuthenticatableInterface ? $user : null;
        }

        // Fallback to findOneBy
        if (method_exists($model, 'findOneBy')) {
            unset($credentials['password']);
            $user = $model::findOneBy($credentials);
            return $user instanceof AuthenticatableInterface ? $user : null;
        }

        return null;
    }

    /**
     * Validate a user against the given credentials
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool
    {
        $password = $credentials['password'] ?? '';

        if (empty($password)) {
            return false;
        }

        return Hash::check($password, $user->getAuthPassword());
    }

    /**
     * Set the model class
     */
    public function setModel(string $model): self
    {
        $this->model = $model;
        return $this;
    }

    /**
     * Get the model class
     */
    public function getModel(): string
    {
        return $this->model;
    }
}
