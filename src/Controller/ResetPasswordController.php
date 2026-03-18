<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Repository\PasswordResetTokenRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class ResetPasswordController
{
    public function __construct(
        private PasswordResetTokenRepository $tokenRepository,
        private UserPasswordHasherInterface $passwordHasher,
        private EntityManagerInterface $entityManager,
    ) {}

    #[Route('/api/reset-password', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $data = \json_decode($request->getContent(), true);
        $tokenValue = $data['token'] ?? '';
        $password = $data['password'] ?? '';

        if (!\is_string($tokenValue) || \strlen($tokenValue) !== 64) {
            return new JsonResponse(
                ['error' => 'Invalid or expired token.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        if (!\is_string($password) || \strlen($password) < 8
            || !\preg_match('/[a-zA-Z]/', $password)
            || !\preg_match('/[0-9]/', $password)
        ) {
            return new JsonResponse(
                ['error' => 'Password must be at least 8 characters with at least one letter and one number.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $selector = \substr($tokenValue, 0, 40);
        $verifier = \substr($tokenValue, 40);

        $token = $this->tokenRepository->findBySelector($selector);

        if ($token === null || $token->isExpired()) {
            return new JsonResponse(
                ['error' => 'Invalid or expired token.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $hashedVerifier = \hash('sha256', $verifier);

        if (!\hash_equals($token->getHashedVerifier(), $hashedVerifier)) {
            return new JsonResponse(
                ['error' => 'Invalid or expired token.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $user = $token->getUser();
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));
        $this->tokenRepository->deleteByUser($user);
        $this->entityManager->flush();

        return new JsonResponse(['message' => 'Password has been reset successfully.']);
    }
}
