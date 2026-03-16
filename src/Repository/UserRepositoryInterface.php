<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Repository;

use PsychedCms\Auth\Entity\User;

interface UserRepositoryInterface
{
    public function findByUsername(string $username): ?User;

    public function findByEmail(string $email): ?User;
}
