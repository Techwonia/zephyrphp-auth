<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

/**
 * User Provider Interface
 *
 * Defines how users are retrieved from storage (database, API, etc.)
 */
interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier
     *
     * @param mixed $identifier The user ID
     * @return AuthenticatableInterface|null
     */
    public function retrieveById($identifier): ?AuthenticatableInterface;

    /**
     * Retrieve a user by their unique identifier and remember token
     *
     * @param mixed $identifier The user ID
     * @param string $token The remember token
     * @return AuthenticatableInterface|null
     */
    public function retrieveByToken($identifier, string $token): ?AuthenticatableInterface;

    /**
     * Update the remember token for the given user
     *
     * @param AuthenticatableInterface $user The user
     * @param string $token The new token
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void;

    /**
     * Retrieve a user by the given credentials
     *
     * @param array $credentials The credentials (excluding password)
     * @return AuthenticatableInterface|null
     */
    public function retrieveByCredentials(array $credentials): ?AuthenticatableInterface;

    /**
     * Validate a user against the given credentials
     *
     * @param AuthenticatableInterface $user The user
     * @param array $credentials The credentials (password)
     * @return bool
     */
    public function validateCredentials(AuthenticatableInterface $user, array $credentials): bool;
}
