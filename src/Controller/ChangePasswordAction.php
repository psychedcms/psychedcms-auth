<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\User;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
#[Route('/api/me/password', methods: ['POST'])]
final readonly class ChangePasswordAction
{
    public function __construct(
        private Security $security,
        private UserPasswordHasherInterface $passwordHasher,
        private EntityManagerInterface $entityManager,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->security->getUser();
        $data = \json_decode($request->getContent(), true);

        if (!\is_array($data)) {
            return new JsonResponse(['error' => 'Invalid JSON'], 400);
        }

        $currentPassword = $data['currentPassword'] ?? null;
        $newPassword = $data['newPassword'] ?? null;

        if (!\is_string($currentPassword) || $currentPassword === '') {
            return new JsonResponse(['error' => 'Current password is required.'], 400);
        }

        if (!\is_string($newPassword) || $newPassword === '') {
            return new JsonResponse(['error' => 'New password is required.'], 400);
        }

        if (!$this->passwordHasher->isPasswordValid($user, $currentPassword)) {
            return new JsonResponse(['error' => 'Current password is incorrect.'], 400);
        }

        if (\strlen($newPassword) < 8) {
            return new JsonResponse(['error' => 'New password must be at least 8 characters.'], 400);
        }

        if (!\preg_match('/[a-zA-Z]/', $newPassword)) {
            return new JsonResponse(['error' => 'New password must contain at least one letter.'], 400);
        }

        if (!\preg_match('/[0-9]/', $newPassword)) {
            return new JsonResponse(['error' => 'New password must contain at least one number.'], 400);
        }

        $hashedPassword = $this->passwordHasher->hashPassword($user, $newPassword);
        $user->setPassword($hashedPassword);

        $this->entityManager->flush();

        return new JsonResponse(['success' => true]);
    }
}
