<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Command;

use Doctrine\ORM\EntityManagerInterface;
use PsychedCms\Auth\Entity\User;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

#[AsCommand(
    name: 'psychedcms:create-admin',
    description: 'Create an admin user',
)]
final class CreateAdminCommand extends Command
{
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('username', InputArgument::REQUIRED, 'Admin username')
            ->addArgument('password', InputArgument::REQUIRED, 'Admin password')
            ->addArgument('email', InputArgument::OPTIONAL, 'Admin email', 'admin@localhost');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        /** @var string $username */
        $username = $input->getArgument('username');
        /** @var string $password */
        $password = $input->getArgument('password');
        /** @var string $email */
        $email = $input->getArgument('email');

        $user = new User($username, $email);
        $user->setRoles(['ROLE_ADMIN']);
        $user->setPassword($this->passwordHasher->hashPassword($user, $password));

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $io->success(\sprintf('Admin user "%s" created.', $username));

        return Command::SUCCESS;
    }
}
