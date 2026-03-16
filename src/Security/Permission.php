<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Security;

enum Permission: string
{
    case ContentCreate = 'content:create';
    case ContentEditOwn = 'content:edit_own';
    case ContentEditAll = 'content:edit_all';
    case ContentDeleteOwn = 'content:delete_own';
    case ContentDeleteAll = 'content:delete_all';
    case ContentPublish = 'content:publish';
    case ContentWorkflow = 'content:workflow';
    case UsersManage = 'users:manage';
    case SettingsManage = 'settings:manage';
    case MediaManage = 'media:manage';
    case SearchGlobal = 'search:global';

    /**
     * @return array<string, list<self>>
     */
    public static function groups(): array
    {
        return [
            'content' => [
                self::ContentCreate,
                self::ContentEditOwn,
                self::ContentEditAll,
                self::ContentDeleteOwn,
                self::ContentDeleteAll,
                self::ContentPublish,
                self::ContentWorkflow,
            ],
            'users' => [
                self::UsersManage,
            ],
            'settings' => [
                self::SettingsManage,
            ],
            'media' => [
                self::MediaManage,
            ],
            'search' => [
                self::SearchGlobal,
            ],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    public static function groupedValues(): array
    {
        $result = [];
        foreach (self::groups() as $group => $permissions) {
            $result[$group] = array_map(fn (self $p) => $p->value, $permissions);
        }

        return $result;
    }

    /**
     * @return list<string>
     */
    public static function defaultsForRole(string $role): array
    {
        return match ($role) {
            'ROLE_ADMIN' => array_map(fn (self $p) => $p->value, self::cases()),
            'ROLE_EDITOR' => [
                self::ContentCreate->value,
                self::ContentEditOwn->value,
                self::ContentDeleteOwn->value,
                self::ContentWorkflow->value,
                self::MediaManage->value,
            ],
            default => [],
        };
    }
}
