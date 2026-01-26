<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

/**
 * Authenticatable Interface
 *
 * Any model that can be authenticated must implement this interface.
 * Typically implemented by your User model.
 */
interface AuthenticatableInterface
{
    /**
     * Get the unique identifier for the user
     *
     * @return mixed Usually the user's ID
     */
    public function getAuthIdentifier();

    /**
     * Get the name of the unique identifier column
     *
     * @return string Usually 'id'
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the password for the user
     *
     * @return string The hashed password
     */
    public function getAuthPassword(): string;

    /**
     * Get the remember token
     *
     * @return string|null The remember token
     */
    public function getRememberToken(): ?string;

    /**
     * Set the remember token
     *
     * @param string $token The token to set
     */
    public function setRememberToken(string $token): void;

    /**
     * Get the column name for the remember token
     *
     * @return string Usually 'remember_token'
     */
    public function getRememberTokenName(): string;
}
