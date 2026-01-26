<?php

declare(strict_types=1);

namespace ZephyrPHP\Auth;

/**
 * Guard Interface
 *
 * Defines how authentication is performed for different contexts
 * (web sessions, API tokens, etc.)
 */
interface GuardInterface
{
    /**
     * Determine if the current user is authenticated
     */
    public function check(): bool;

    /**
     * Determine if the current user is a guest
     */
    public function guest(): bool;

    /**
     * Get the currently authenticated user
     */
    public function user(): ?AuthenticatableInterface;

    /**
     * Get the ID of the currently authenticated user
     *
     * @return mixed|null
     */
    public function id();

    /**
     * Validate a user's credentials
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = []): bool;

    /**
     * Set the current user
     *
     * @param AuthenticatableInterface $user
     */
    public function setUser(AuthenticatableInterface $user): void;
}
