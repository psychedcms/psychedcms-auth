<?php

declare(strict_types=1);

namespace PsychedCms\Auth\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\Metadata\Post;
use ApiPlatform\State\ProcessorInterface;
use PsychedCms\Auth\Entity\User;
use PsychedCms\Auth\Repository\UserRepository;
use PsychedCms\Auth\Service\InvitationMailer;
use PsychedCms\Auth\Service\InvitationTokenGenerator;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

final readonly class UserPasswordProcessor implements ProcessorInterface
{
    public function __construct(
        private ProcessorInterface $persistProcessor,
        private UserPasswordHasherInterface $passwordHasher,
        private InvitationTokenGenerator $invitationTokenGenerator,
        private InvitationMailer $invitationMailer,
        private UserRepository $userRepository,
    ) {
    }

    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = []): mixed
    {
        if (!$data instanceof User) {
            return $this->persistProcessor->process($data, $operation, $uriVariables, $context);
        }

        $isCreate = $operation instanceof Post;

        if ($isCreate) {
            // Auto-generate username from email if not provided or empty
            if ($data->getUsername() === '' || $data->getUsername() === $data->getEmail()) {
                $baseUsername = \explode('@', $data->getEmail())[0];
                $username = $baseUsername;
                $suffix = 1;
                while ($this->userRepository->findByUsername($username) !== null) {
                    $username = $baseUsername . $suffix;
                    ++$suffix;
                }
                $data->setUsername($username);
            }

            if ($data->getPassword() !== '') {
                // Password provided — hash and activate immediately
                $data->setPassword($this->passwordHasher->hashPassword($data, $data->getPassword()));
                $data->setActivatedAt(new \DateTimeImmutable());
            } else {
                // No password — set a random unusable password, leave unactivated
                $data->setPassword($this->passwordHasher->hashPassword($data, \bin2hex(\random_bytes(32))));
            }
        } else {
            // Update: only hash if password changed
            if ($data->getPassword() !== '') {
                $data->setPassword($this->passwordHasher->hashPassword($data, $data->getPassword()));
            }
        }

        $result = $this->persistProcessor->process($data, $operation, $uriVariables, $context);

        // After create: if not activated, send invitation email
        if ($isCreate && !$data->isActivated()) {
            $token = $this->invitationTokenGenerator->generate($data);
            $this->invitationMailer->sendInvitation($data, $token);
        }

        return $result;
    }
}
