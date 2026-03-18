<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Service;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\PasswordResetToken;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Repository\PasswordResetTokenRepository;

final readonly class PasswordResetTokenGenerator
{
    public function __construct(
        private PasswordResetTokenRepository $tokenRepository,
        private EntityManagerInterface $entityManager,
    ) {}

    public function generate(User $user): string
    {
        $this->tokenRepository->deleteByUser($user);

        $tokenBytes = \bin2hex(\random_bytes(32));
        $selector = \substr($tokenBytes, 0, 40);
        $verifier = \substr($tokenBytes, 40);
        $hashedVerifier = \hash('sha256', $verifier);

        $token = new PasswordResetToken(
            $user,
            $selector,
            $hashedVerifier,
            new \DateTimeImmutable('+1 hour'),
        );

        $this->entityManager->persist($token);
        $this->entityManager->flush();

        return $tokenBytes;
    }
}
