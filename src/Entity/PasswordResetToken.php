<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Entity;

use Doctrine\ORM\Mapping as ORM;
use PsychedCms\Auth\Repository\PasswordResetTokenRepository;
use Symfony\Component\Uid\Ulid;

#[ORM\Entity(repositoryClass: PasswordResetTokenRepository::class)]
#[ORM\Table(name: 'api_password_reset_tokens')]
class PasswordResetToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid')]
    private Ulid $id;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $user;

    #[ORM\Column(length: 40, unique: true)]
    private string $selector;

    #[ORM\Column(length: 100)]
    private string $hashedVerifier;

    #[ORM\Column]
    private \DateTimeImmutable $requestedAt;

    #[ORM\Column]
    private \DateTimeImmutable $expiresAt;

    public function __construct(User $user, string $selector, string $hashedVerifier, \DateTimeImmutable $expiresAt)
    {
        $this->id = new Ulid();
        $this->user = $user;
        $this->selector = $selector;
        $this->hashedVerifier = $hashedVerifier;
        $this->requestedAt = new \DateTimeImmutable();
        $this->expiresAt = $expiresAt;
    }

    public function getId(): Ulid
    {
        return $this->id;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getSelector(): string
    {
        return $this->selector;
    }

    public function getHashedVerifier(): string
    {
        return $this->hashedVerifier;
    }

    public function getRequestedAt(): \DateTimeImmutable
    {
        return $this->requestedAt;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt < new \DateTimeImmutable();
    }
}
