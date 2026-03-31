<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Controller;

use PsychedCms\Auth\Contract\MeDataEnricherInterface;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Security\PermissionRegistry;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

#[AsController]
#[Route('/api/me', methods: ['GET'])]
final readonly class GetMeAction
{
    /**
     * @param iterable<MeDataEnricherInterface> $enrichers
     */
    public function __construct(
        private Security $security,
        private PermissionRegistry $permissionRegistry,
        #[AutowireIterator('psychedcms.me_data_enricher')]
        private iterable $enrichers,
    ) {}

    public function __invoke(): JsonResponse
    {
        /** @var User $user */
        $user = $this->security->getUser();

        $data = [
            'id' => (string) $user->getId(),
            'username' => $user->getUsername(),
            'email' => $user->getEmail(),
            'locale' => $user->getLocale(),
            'roles' => $user->getRoles(),
            'permissions' => $this->permissionRegistry->getPermissionsForUser($user),
            'avatar' => $user->getAvatar(),
            'activatedAt' => $user->getActivatedAt()?->format('c'),
        ];

        foreach ($this->enrichers as $enricher) {
            $enricher->enrich($user, $data);
        }

        return new JsonResponse($data);
    }
}
