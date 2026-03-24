<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Service;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\InvitationToken;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Repository\InvitationTokenRepository;

final readonly class InvitationTokenGenerator
{
    public function __construct(
        private InvitationTokenRepository $tokenRepository,
        private EntityManagerInterface $entityManager,
    ) {}

    public function generate(User $user): string
    {
        $this->tokenRepository->deleteByUser($user);

        $tokenBytes = \bin2hex(\random_bytes(32));
        $selector = \substr($tokenBytes, 0, 40);
        $verifier = \substr($tokenBytes, 40);
        $hashedVerifier = \hash('sha256', $verifier);

        $token = new InvitationToken(
            $user,
            $selector,
            $hashedVerifier,
            new \DateTimeImmutable('+24 hours'),
        );

        $this->entityManager->persist($token);
        $this->entityManager->flush();

        return $tokenBytes;
    }
}
