<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Command;

use PsychedCms\Auth\Repository\PasswordResetTokenRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'psychedcms:auth:clean-expired-tokens',
    description: 'Remove expired password reset tokens',
)]
final class CleanExpiredTokensCommand extends Command
{
    public function __construct(
        private readonly PasswordResetTokenRepository $tokenRepository,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $deleted = $this->tokenRepository->deleteExpired();
        $io->success(\sprintf('Deleted %d expired token(s).', $deleted));

        return Command::SUCCESS;
    }
}
