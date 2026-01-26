<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

/**
 * Authenticatable Trait
 *
 * Add this trait to your User model to implement AuthenticatableInterface.
 *
 * Usage:
 *   class User extends Model implements AuthenticatableInterface
 *   {
 *       use Authenticatable;
 *   }
 */
trait Authenticatable
{
    /**
     * Get the unique identifier for the user
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->{$this->getAuthIdentifierName()};
    }

    /**
     * Get the name of the unique identifier column
     */
    public function getAuthIdentifierName(): string
    {
        return $this->primaryKey ?? 'id';
    }

    /**
     * Get the password for the user
     */
    public function getAuthPassword(): string
    {
        return $this->password ?? '';
    }

    /**
     * Get the remember token
     */
    public function getRememberToken(): ?string
    {
        return $this->{$this->getRememberTokenName()} ?? null;
    }

    /**
     * Set the remember token
     */
    public function setRememberToken(string $token): void
    {
        $this->{$this->getRememberTokenName()} = $token;
    }

    /**
     * Get the column name for the remember token
     */
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
