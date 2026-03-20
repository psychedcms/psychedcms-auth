<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Content;

use ApiPlatform\Metadata\ApiProperty;
use Doctrine\ORM\Mapping as ORM;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Core\Attribute\Field\RelationField;
use Symfony\Component\Serializer\Annotation\Groups;

trait AuthorTrait
{
    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: true)]
    #[RelationField(label: 'Author', reference: 'users', displayField: 'username', group: 'meta')]
    #[Groups(['content:read', 'content:write'])]
    private ?User $author = null;

    public function getAuthor(): ?User
    {
        return $this->author;
    }

    public function setAuthor(?User $author): static
    {
        $this->author = $author;

        return $this;
    }
}
