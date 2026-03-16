<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

use PsychedCms\Auth\Repository\RolePermissionRepository;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class PermissionRegistry
{
    /** @var array<string, list<string>>|null */
    private ?array $cache = null;

    public function __construct(
        private readonly RolePermissionRepository $repository,
        private readonly RoleHierarchyInterface $roleHierarchy,
    ) {
    }

    public function hasPermission(string $role, string $permission): bool
    {
        $permissions = $this->loadAll()[$role] ?? [];

        return \in_array($permission, $permissions, true);
    }

    public function userHasPermission(UserInterface $user, string $permission): bool
    {
        $effectiveRoles = $this->roleHierarchy->getReachableRoleNames($user->getRoles());

        foreach ($effectiveRoles as $role) {
            if ($this->hasPermission($role, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function getPermissionsForUser(UserInterface $user): array
    {
        $effectiveRoles = $this->roleHierarchy->getReachableRoleNames($user->getRoles());
        $permissions = [];

        foreach ($effectiveRoles as $role) {
            foreach ($this->loadAll()[$role] ?? [] as $permission) {
                $permissions[] = $permission;
            }
        }

        return array_values(array_unique($permissions));
    }

    public function invalidate(): void
    {
        $this->cache = null;
    }

    /**
     * @return array<string, list<string>>
     */
    private function loadAll(): array
    {
        if ($this->cache === null) {
            $this->cache = $this->repository->getPermissionsGroupedByRole();
        }

        return $this->cache;
    }
}
