<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Repository\UserRepository;
use PsychedCms\Auth\Service\InvitationMailer;
use PsychedCms\Auth\Service\InvitationTokenGenerator;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
final class RegisterController
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly EntityManagerInterface $entityManager,
        private readonly ?object $jwtManager,
        private readonly InvitationTokenGenerator $invitationTokenGenerator,
        private readonly InvitationMailer $invitationMailer,
        private readonly RateLimiterFactory $registerLimiter,
        private readonly string $cookieDomain,
        private readonly string $appEnv,
    ) {}

    #[Route('/api/register', methods: ['POST'])]
    public function __invoke(Request $request): JsonResponse
    {
        $limiter = $this->registerLimiter->create($request->getClientIp() ?? 'unknown');
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
        $password = $data['password'] ?? '';

        if (!\is_string($email) || !\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse(
                ['error' => 'A valid email address is required.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        if ($this->userRepository->findByEmail($email) !== null) {
            return new JsonResponse(
                ['error' => 'This email is already registered.'],
                Response::HTTP_CONFLICT,
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

        $baseUsername = \explode('@', $email)[0];
        $username = $baseUsername;
        $suffix = 1;
        while ($this->userRepository->findByUsername($username) !== null) {
            $username = $baseUsername . $suffix;
            ++$suffix;
        }

        $user = new User($username, $email);
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $verificationToken = $this->invitationTokenGenerator->generate($user);
        $this->invitationMailer->sendVerification($user, $verificationToken);

        // JWT token creation — only when Lexik is installed
        $token = $this->jwtManager !== null ? $this->jwtManager->create($user) : null;

        $response = new JsonResponse([
            'token' => $token,
            'user' => [
                'id' => (string) $user->getId(),
                'username' => $user->getUsername(),
                'email' => $user->getEmail(),
                'roles' => $user->getRoles(),
                'locale' => $user->getLocale(),
                'avatar' => $user->getAvatar(),
                'banner' => $user->getBanner(),
                'activatedAt' => null,
            ],
        ], Response::HTTP_CREATED);

        if ($token !== null) {
            $response->headers->setCookie(
                Cookie::create('jwt')
                    ->withValue($token)
                    ->withExpires(0)
                    ->withPath('/')
                    ->withDomain($this->cookieDomain)
                    ->withSecure($this->appEnv === 'prod')
                    ->withHttpOnly(true)
                    ->withSameSite('lax')
            );
        }

        return $response;
    }
}
