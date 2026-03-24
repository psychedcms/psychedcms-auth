<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Service\InvitationMailer;
use PsychedCms\Auth\Service\InvitationTokenGenerator;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class ResendVerificationController
{
    public function __construct(
        private Security $security,
        private InvitationTokenGenerator $invitationTokenGenerator,
        private InvitationMailer $invitationMailer,
        private RateLimiterFactory $resendVerificationLimiter,
    ) {}

    #[Route('/api/resend-verification', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $limiter = $this->resendVerificationLimiter->create($request->getClientIp() ?? 'unknown');
        $limit = $limiter->consume();
        if (!$limit->isAccepted()) {
            return new JsonResponse(
                ['message' => 'Too many requests. Please try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => (string) ($limit->getRetryAfter()->getTimestamp() - time())],
            );
        }

        /** @var User $user */
        $user = $this->security->getUser();

        if ($user->isActivated()) {
            return new JsonResponse(
                ['message' => 'Email already verified.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $token = $this->invitationTokenGenerator->generate($user);
        $this->invitationMailer->sendVerification($user, $token);

        return new JsonResponse(['message' => 'Verification email sent.']);
    }
}
