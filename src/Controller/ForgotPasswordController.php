<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use PsychedCms\Auth\Repository\PasswordResetTokenRepository;
use PsychedCms\Auth\Repository\UserRepository;
use PsychedCms\Auth\Service\PasswordResetMailer;
use PsychedCms\Auth\Service\PasswordResetTokenGenerator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final readonly class ForgotPasswordController
{
    public function __construct(
        private UserRepository $userRepository,
        private PasswordResetTokenRepository $tokenRepository,
        private PasswordResetTokenGenerator $tokenGenerator,
        private PasswordResetMailer $mailer,
        private RateLimiterFactory $forgotPasswordLimiter,
    ) {}

    #[Route('/api/forgot-password', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $limiter = $this->forgotPasswordLimiter->create($request->getClientIp() ?? 'unknown');
        $limit = $limiter->consume();
        if (!$limit->isAccepted()) {
            return new JsonResponse(
                ['message' => 'Too many requests. Please try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => (string) ($limit->getRetryAfter()->getTimestamp() - time())],
            );
        }

        $data = \json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';

        if (!\is_string($email) || !\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse(['message' => 'If this email exists, a reset link has been sent.']);
        }

        $user = $this->userRepository->findByEmail($email);

        if ($user !== null) {
            $recentCount = $this->tokenRepository->countRecentByUser(
                $user,
                new \DateTimeImmutable('-15 minutes'),
            );

            if ($recentCount < 3) {
                $token = $this->tokenGenerator->generate($user);
                $this->mailer->send($user, $token);
            }
        }

        return new JsonResponse(['message' => 'If this email exists, a reset link has been sent.']);
    }
}
