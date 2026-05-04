<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\User;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

final class ServiceTokenAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly string $serviceToken,
        private readonly EntityManagerInterface $entityManager,
    ) {}

    public function supports(Request $request): ?bool
    {
        if ($this->serviceToken === '') {
            return false;
        }

        $authHeader = $request->headers->get('Authorization', '');
        if (!str_starts_with($authHeader, 'Bearer ')) {
            return false;
        }

        $token = substr($authHeader, 7);

        // Only handle non-JWT tokens (JWTs have dots, service tokens don't)
        // This lets the JWT authenticator handle actual JWTs
        if (str_contains($token, '.')) {
            return false;
        }

        return $token === $this->serviceToken;
    }

    public function authenticate(Request $request): Passport
    {
        $authHeader = $request->headers->get('Authorization', '');
        $token = substr($authHeader, 7);

        if ($token !== $this->serviceToken) {
            throw new CustomUserMessageAuthenticationException('Invalid service token');
        }

        // Find or create a system service user
        return new SelfValidatingPassport(
            new UserBadge('service@system.local', function (string $identifier): User {
                $repo = $this->entityManager->getRepository(User::class);
                $user = $repo->findOneBy(['email' => $identifier]);

                if ($user === null) {
                    $user = new User('service', $identifier);
                    $user->setRoles(['ROLE_ADMIN']);
                    $user->setPassword(bin2hex(random_bytes(32)));
                    $this->entityManager->persist($user);
                    $this->entityManager->flush();
                }

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(
            ['code' => Response::HTTP_UNAUTHORIZED, 'message' => $exception->getMessageKey()],
            Response::HTTP_UNAUTHORIZED
        );
    }
}
