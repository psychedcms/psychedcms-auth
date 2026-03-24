<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Repository\InvitationTokenRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class VerifyEmailController
{
    public function __construct(
        private InvitationTokenRepository $tokenRepository,
        private EntityManagerInterface $entityManager,
    ) {}

    #[Route('/api/verify-email', methods: ['GET'])]
    public function __invoke(Request $request): JsonResponse
    {
        $tokenValue = $request->query->getString('token');

        if (\strlen($tokenValue) !== 64) {
            return new JsonResponse(
                ['error' => 'Invalid or expired verification link.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $selector = \substr($tokenValue, 0, 40);
        $verifier = \substr($tokenValue, 40);

        $token = $this->tokenRepository->findBySelector($selector);

        if ($token === null || $token->isExpired()) {
            return new JsonResponse(
                ['error' => 'Invalid or expired verification link.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $hashedVerifier = \hash('sha256', $verifier);

        if (!\hash_equals($token->getHashedVerifier(), $hashedVerifier)) {
            return new JsonResponse(
                ['error' => 'Invalid or expired verification link.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $user = $token->getUser();
        $user->setActivatedAt(new \DateTimeImmutable());
        $this->tokenRepository->deleteByUser($user);
        $this->entityManager->flush();

        return new JsonResponse(['message' => 'Email verified successfully.']);
    }
}
