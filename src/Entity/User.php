<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Entity;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Delete;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Patch;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Put;
use Doctrine\ORM\Mapping as ORM;
use Override;
use PsychedCms\Auth\Repository\UserRepository;
use PsychedCms\Media\Attribute\ImageField;
use PsychedCms\Auth\State\UserPasswordProcessor;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Serializer\Annotation\Groups;
use Symfony\Component\Serializer\Annotation\SerializedName;
use Symfony\Component\Uid\Ulid;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(name: 'api_users')]
#[ApiResource(
    shortName: 'User',
    operations: [
        new Get(
            uriTemplate: '/profiles/{username}',
            security: 'true',
            normalizationContext: ['groups' => ['profile:read']],
        ),
        new GetCollection(security: 'is_granted("PERMISSION_USERS_MANAGE")'),
        new Get(security: 'is_granted("PERMISSION_USERS_MANAGE")'),
        new Post(security: 'is_granted("PERMISSION_USERS_MANAGE")', processor: UserPasswordProcessor::class),
        new Put(security: 'is_granted("PERMISSION_USERS_MANAGE")', processor: UserPasswordProcessor::class),
        new Patch(security: 'is_granted("PERMISSION_USERS_MANAGE")'),
        new Delete(security: 'is_granted("PERMISSION_USERS_MANAGE")'),
    ],
    normalizationContext: ['groups' => ['user:read']],
    denormalizationContext: ['groups' => ['user:write']],
)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'ulid')]
    #[ApiProperty(identifier: false, readable: false)]
    private Ulid $id;

    #[ORM\Column(length: 180, unique: true)]
    #[Groups(['user:read', 'user:write', 'content:read', 'profile:read'])]
    #[ApiProperty(identifier: true)]
    #[\PsychedCms\Elasticsearch\Attribute\IndexedField(type: 'keyword', facetable: true)]
    private string $username;

    #[ORM\Column(length: 180, unique: true)]
    #[Groups(['user:read', 'user:write'])]
    private string $email;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    #[Groups(['user:read', 'user:write'])]
    private array $roles = [];

    #[ORM\Column]
    #[Groups(['user:write'])]
    private string $password = '';

    #[ORM\Column(length: 10, nullable: true)]
    #[Groups(['user:read', 'user:write'])]
    private ?string $locale = null;

    #[ORM\Column(type: 'json', nullable: true)]
    #[ImageField(label: 'Avatar', group: 'media', dimensions: ['avatar' => [400, 400]])]
    #[Groups(['user:read', 'content:read', 'profile:read'])]
    private ?array $avatar = null;

    #[ORM\Column(type: 'json', nullable: true)]
    #[ImageField(label: 'Banner', group: 'media', dimensions: ['banner' => [1600, 400]])]
    #[Groups(['user:read', 'profile:read'])]
    private ?array $banner = null;

    #[ORM\Column(nullable: true)]
    #[Groups(['user:read'])]
    private ?\DateTimeImmutable $activatedAt = null;

    /** @var array{lat: float, lng: float, name: string}|null */
    #[ORM\Column(type: 'json', nullable: true)]
    #[Groups(['user:read', 'user:write'])]
    private ?array $defaultLocation = null;

    #[ORM\Column(type: 'text', nullable: true)]
    #[Groups(['user:read', 'user:write', 'profile:read'])]
    private ?string $bio = null;

    #[ORM\Column(length: 10, options: ['default' => 'public'])]
    #[Groups(['user:read', 'user:write', 'profile:read'])]
    private string $profileVisibility = 'public';

    #[ORM\Column(type: 'boolean', options: ['default' => true])]
    #[Groups(['user:read', 'user:write', 'profile:read'])]
    private bool $showFollowing = true;

    #[ORM\Column(type: 'integer', options: ['default' => 0])]
    #[Groups(['user:read', 'profile:read'])]
    private int $followerCount = 0;

    #[ORM\Column(type: 'integer', options: ['default' => 0])]
    #[Groups(['user:read', 'profile:read'])]
    private int $followingCount = 0;

    public function __construct(string $username, string $email)
    {
        $this->id = new Ulid();
        $this->username = $username;
        $this->email = $email;
    }

    public function getId(): Ulid
    {
        return $this->id;
    }

    #[Groups(['user:read', 'profile:read'])]
    #[SerializedName('id')]
    public function getApiIdentifier(): string
    {
        return $this->username;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    #[Override]
    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';

        return \array_values(\array_unique($roles));
    }

    /**
     * @param list<string> $roles
     */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    #[Override]
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function getLocale(): ?string
    {
        return $this->locale;
    }

    public function setLocale(?string $locale): static
    {
        $this->locale = $locale;

        return $this;
    }

    public function getAvatar(): ?array
    {
        return $this->avatar;
    }

    public function setAvatar(?array $avatar): static
    {
        $this->avatar = $avatar;

        return $this;
    }

    public function getBanner(): ?array
    {
        return $this->banner;
    }

    public function setBanner(?array $banner): static
    {
        $this->banner = $banner;

        return $this;
    }

    public function getActivatedAt(): ?\DateTimeImmutable
    {
        return $this->activatedAt;
    }

    public function setActivatedAt(?\DateTimeImmutable $activatedAt): static
    {
        $this->activatedAt = $activatedAt;

        return $this;
    }

    public function isActivated(): bool
    {
        return $this->activatedAt !== null;
    }

    /** @return array{lat: float, lng: float, name: string}|null */
    public function getDefaultLocation(): ?array
    {
        return $this->defaultLocation;
    }

    /** @param array{lat: float, lng: float, name: string}|null $defaultLocation */
    public function setDefaultLocation(?array $defaultLocation): static
    {
        $this->defaultLocation = $defaultLocation;

        return $this;
    }

    public function getBio(): ?string
    {
        return $this->bio;
    }

    public function setBio(?string $bio): static
    {
        $this->bio = $bio;

        return $this;
    }

    public function getProfileVisibility(): string
    {
        return $this->profileVisibility;
    }

    public function setProfileVisibility(string $profileVisibility): static
    {
        $this->profileVisibility = $profileVisibility;

        return $this;
    }

    public function isProfilePrivate(): bool
    {
        return $this->profileVisibility === 'private';
    }

    public function getShowFollowing(): bool
    {
        return $this->showFollowing;
    }

    public function setShowFollowing(bool $showFollowing): static
    {
        $this->showFollowing = $showFollowing;

        return $this;
    }

    public function getFollowerCount(): int
    {
        return $this->followerCount;
    }

    public function setFollowerCount(int $followerCount): static
    {
        $this->followerCount = $followerCount;

        return $this;
    }

    public function incrementFollowerCount(): static
    {
        ++$this->followerCount;

        return $this;
    }

    public function decrementFollowerCount(): static
    {
        $this->followerCount = \max(0, $this->followerCount - 1);

        return $this;
    }

    public function getFollowingCount(): int
    {
        return $this->followingCount;
    }

    public function setFollowingCount(int $followingCount): static
    {
        $this->followingCount = $followingCount;

        return $this;
    }

    public function incrementFollowingCount(): static
    {
        ++$this->followingCount;

        return $this;
    }

    public function decrementFollowingCount(): static
    {
        $this->followingCount = \max(0, $this->followingCount - 1);

        return $this;
    }

    #[Override]
    public function eraseCredentials(): void {}
}
