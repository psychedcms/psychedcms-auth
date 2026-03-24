<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use PsychedCms\Auth\Repository\UserRepository;
use PsychedCms\Auth\Service\InvitationMailer;
use PsychedCms\Auth\Service\InvitationTokenGenerator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[AsController]
final readonly class ResendInvitationController
{
    public function __construct(
        private UserRepository $userRepository,
        private InvitationTokenGenerator $invitationTokenGenerator,
        private InvitationMailer $invitationMailer,
        private RateLimiterFactory $resendInvitationLimiter,
    ) {}

    #[Route('/api/invite/{username}/resend', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function __invoke(string $username, Request $request): JsonResponse
    {
        $limiter = $this->resendInvitationLimiter->create($request->getClientIp() ?? 'unknown');
        $limit = $limiter->consume();
        if (!$limit->isAccepted()) {
            return new JsonResponse(
                ['message' => 'Too many requests. Please try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => (string) ($limit->getRetryAfter()->getTimestamp() - time())],
            );
        }

        $user = $this->userRepository->findByUsername($username);

        if ($user === null) {
            return new JsonResponse(
                ['error' => 'User not found.'],
                Response::HTTP_NOT_FOUND,
            );
        }

        if ($user->isActivated()) {
            return new JsonResponse(
                ['error' => 'User is already activated.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $token = $this->invitationTokenGenerator->generate($user);
        $this->invitationMailer->sendInvitation($user, $token);

        return new JsonResponse(['message' => 'Invitation resent successfully.']);
    }
}
