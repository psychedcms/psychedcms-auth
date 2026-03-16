<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Votes on PERMISSION_* attributes by converting them to permission strings
 * and checking via PermissionRegistry.
 *
 * Example: PERMISSION_CONTENT_CREATE → content:create
 */
final class PermissionVoter extends Voter
{
    private const PREFIX = 'PERMISSION_';

    public function __construct(
        private readonly PermissionRegistry $permissionRegistry,
    ) {
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return str_starts_with($attribute, self::PREFIX);
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        if (!$user instanceof \Symfony\Component\Security\Core\User\UserInterface) {
            return false;
        }

        $permission = $this->attributeToPermission($attribute);

        return $this->permissionRegistry->userHasPermission($user, $permission);
    }

    /**
     * PERMISSION_CONTENT_CREATE → content:create
     * PERMISSION_CONTENT_EDIT_OWN → content:edit_own
     * PERMISSION_SEARCH_GLOBAL → search:global
     */
    private function attributeToPermission(string $attribute): string
    {
        $raw = substr($attribute, \strlen(self::PREFIX));
        $lower = strtolower($raw);

        // Split on first underscore to get group:rest
        $pos = strpos($lower, '_');
        if ($pos === false) {
            return $lower;
        }

        $group = substr($lower, 0, $pos);
        $rest = substr($lower, $pos + 1);

        return $group . ':' . $rest;
    }
}
