<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Repository;

use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use PsychedCms\Auth\Entity\InvitationToken;
use PsychedCms\Auth\Entity\User;

/**
 * @extends ServiceEntityRepository<InvitationToken>
 */
class InvitationTokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, InvitationToken::class);
    }

    public function findBySelector(string $selector): ?InvitationToken
    {
        return $this->findOneBy(['selector' => $selector]);
    }

    public function deleteByUser(User $user): void
    {
        $this->createQueryBuilder('t')
            ->delete()
            ->where('t.user = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->execute();
    }

    public function deleteExpired(): int
    {
        return (int) $this->createQueryBuilder('t')
            ->delete()
            ->where('t.expiresAt < :now')
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->execute();
    }
}
