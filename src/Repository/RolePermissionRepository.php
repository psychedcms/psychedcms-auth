<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use PsychedCms\Auth\Entity\RolePermission;

/**
 * @extends ServiceEntityRepository<RolePermission>
 */
class RolePermissionRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, RolePermission::class);
    }

    /**
     * @return list<string>
     */
    public function findPermissionsByRole(string $role): array
    {
        $rows = $this->findBy(['role' => $role]);

        return array_map(fn (RolePermission $rp) => $rp->getPermission(), $rows);
    }

    /**
     * @return array<string, list<string>>
     */
    public function getPermissionsGroupedByRole(): array
    {
        $all = $this->findAll();
        $grouped = [];

        foreach ($all as $rp) {
            $grouped[$rp->getRole()][] = $rp->getPermission();
        }

        return $grouped;
    }

    /**
     * @param list<string> $permissions
     */
    public function replaceForRole(string $role, array $permissions): void
    {
        $em = $this->getEntityManager();

        $em->createQueryBuilder()
            ->delete(RolePermission::class, 'rp')
            ->where('rp.role = :role')
            ->setParameter('role', $role)
            ->getQuery()
            ->execute();

        foreach ($permissions as $permission) {
            $em->persist(new RolePermission($role, $permission));
        }

        $em->flush();
    }
}
