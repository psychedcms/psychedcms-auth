<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Entity;

use Doctrine\ORM\Mapping as ORM;
use PsychedCms\Auth\Repository\RolePermissionRepository;
use Symfony\Component\Uid\Ulid;

#[ORM\Entity(repositoryClass: RolePermissionRepository::class)]
#[ORM\Table(name: 'api_role_permissions')]
#[ORM\UniqueConstraint(name: 'uniq_role_permission', columns: ['role', 'permission'])]
class RolePermission
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid')]
    private Ulid $id;

    #[ORM\Column(length: 50)]
    private string $role;

    #[ORM\Column(length: 100)]
    private string $permission;

    public function __construct(string $role, string $permission)
    {
        $this->id = new Ulid();
        $this->role = $role;
        $this->permission = $permission;
    }

    public function getId(): Ulid
    {
        return $this->id;
    }

    public function getRole(): string
    {
        return $this->role;
    }

    public function getPermission(): string
    {
        return $this->permission;
    }
}
