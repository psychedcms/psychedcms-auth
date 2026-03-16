<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Content;

use PsychedCms\Auth\Entity\User;

interface AuthorAwareInterface
{
    public function getAuthor(): ?User;

    public function setAuthor(?User $author): static;
}
