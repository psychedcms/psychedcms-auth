<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Contract;

use PsychedCms\Auth\Entity\User;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('psychedcms.me_update_handler')]
interface MeUpdateHandlerInterface
{
    /**
     * Process module-specific fields from the PUT /api/me request.
     * Modify entities as needed -- flush will be called after all handlers.
     *
     * @param array<string, mixed> $requestData The full request payload
     * @param array<string, mixed> &$responseData Response data to enrich
     */
    public function handleUpdate(User $user, array $requestData, array &$responseData): void;
}
