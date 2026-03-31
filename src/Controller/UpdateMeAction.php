<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Contract\MeDataEnricherInterface;
use PsychedCms\Auth\Contract\MeUpdateHandlerInterface;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Security\PermissionRegistry;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
#[Route('/api/me', methods: ['PUT'])]
final readonly class UpdateMeAction
{
    /**
     * @param iterable<MeUpdateHandlerInterface> $updateHandlers
     * @param iterable<MeDataEnricherInterface> $enrichers
     */
    public function __construct(
        private Security $security,
        private PermissionRegistry $permissionRegistry,
        private EntityManagerInterface $entityManager,
        private UserPasswordHasherInterface $passwordHasher,
        #[AutowireIterator('psychedcms.me_update_handler')]
        private iterable $updateHandlers,
        #[AutowireIterator('psychedcms.me_data_enricher')]
        private iterable $enrichers,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->security->getUser();
        $data = \json_decode($request->getContent(), true);

        if (!\is_array($data)) {
            return new JsonResponse(['error' => 'Invalid JSON'], 400);
        }

        // Core user field updates
        if (\array_key_exists('email', $data) && \is_string($data['email']) && $data['email'] !== '' && $data['email'] !== $user->getEmail()) {
            $password = $data['password'] ?? null;
            if (!\is_string($password) || $password === '') {
                return new JsonResponse(['error' => 'Password required to change email.'], 400);
            }
            if (!$this->passwordHasher->isPasswordValid($user, $password)) {
                return new JsonResponse(['error' => 'Wrong password.'], 400);
            }
            $user->setEmail($data['email']);
        }

        if (\array_key_exists('username', $data) && \is_string($data['username']) && $data['username'] !== '') {
            $user->setUsername($data['username']);
        }

        if (\array_key_exists('locale', $data)) {
            $user->setLocale(\is_string($data['locale']) ? $data['locale'] : null);
        }

        // Build response data with core fields
        $responseData = [
            'id' => (string) $user->getId(),
            'username' => $user->getUsername(),
            'email' => $user->getEmail(),
            'locale' => $user->getLocale(),
            'roles' => $user->getRoles(),
            'permissions' => $this->permissionRegistry->getPermissionsForUser($user),
            'avatar' => $user->getAvatar(),
            'activatedAt' => $user->getActivatedAt()?->format('c'),
        ];

        // Let modules handle their own fields
        foreach ($this->updateHandlers as $handler) {
            $handler->handleUpdate($user, $data, $responseData);
        }

        $this->entityManager->flush();

        // Enrich response (enrichers may read flushed state)
        foreach ($this->enrichers as $enricher) {
            $enricher->enrich($user, $responseData);
        }

        return new JsonResponse($responseData);
    }
}
