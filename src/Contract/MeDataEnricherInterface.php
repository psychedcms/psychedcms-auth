<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Contract;

use PsychedCms\Auth\Entity\User;
use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

#[AutoconfigureTag('psychedcms.me_data_enricher')]
interface MeDataEnricherInterface
{
    /**
     * @param array<string, mixed> &$data
     */
    public function enrich(User $user, array &$data): void;
}
