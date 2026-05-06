<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

final class PermissionCatalog
{
    /**
     * @param array<string, list<string>> $contributedPermissions Permissions contributed by other bundles via prepended `psychedcms_auth.permissions` config
     */
    public function __construct(private readonly array $contributedPermissions = [])
    {
    }

    /**
     * @return array<string, list<string>>
     */
    public function groupedValues(): array
    {
        $result = Permission::groupedValues();

        foreach ($this->contributedPermissions as $group => $permissions) {
            $existing = $result[$group] ?? [];
            $result[$group] = array_values(array_unique([...$existing, ...$permissions]));
        }

        ksort($result);

        return $result;
    }
}
