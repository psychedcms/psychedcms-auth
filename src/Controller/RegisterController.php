<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
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
final readonly class RegisterController
{
    public function __construct(
        private UserRepository $userRepository,
        private UserPasswordHasherInterface $passwordHasher,
        private EntityManagerInterface $entityManager,
        private JWTTokenManagerInterface $jwtManager,
        private InvitationTokenGenerator $invitationTokenGenerator,
        private InvitationMailer $invitationMailer,
        private RateLimiterFactory $registerLimiter,
        private string $cookieDomain,
        private string $appEnv,
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

        // Validate email
        if (!\is_string($email) || !\filter_var($email, \FILTER_VALIDATE_EMAIL)) {
            return new JsonResponse(
                ['error' => 'A valid email address is required.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // Check email uniqueness
        if ($this->userRepository->findByEmail($email) !== null) {
            return new JsonResponse(
                ['error' => 'This email is already registered.'],
                Response::HTTP_CONFLICT,
            );
        }

        // Validate password
        if (!\is_string($password) || \strlen($password) < 8
            || !\preg_match('/[a-zA-Z]/', $password)
            || !\preg_match('/[0-9]/', $password)
        ) {
            return new JsonResponse(
                ['error' => 'Password must be at least 8 characters with at least one letter and one number.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        // Generate username from email prefix, with numeric suffix on collision
        $baseUsername = \explode('@', $email)[0];
        $username = $baseUsername;
        $suffix = 1;
        while ($this->userRepository->findByUsername($username) !== null) {
            $username = $baseUsername . $suffix;
            ++$suffix;
        }

        $user = new User($username, $email);
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));
        // activatedAt stays null — user must verify email

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        // Send verification email
        $verificationToken = $this->invitationTokenGenerator->generate($user);
        $this->invitationMailer->sendVerification($user, $verificationToken);

        $token = $this->jwtManager->create($user);

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

        return $response;
    }
}
