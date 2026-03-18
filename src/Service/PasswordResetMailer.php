<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Service;

use PsychedCms\Auth\Entity\User;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

final readonly class PasswordResetMailer
{
    public function __construct(
        private MailerInterface $mailer,
        private string $adminUrl,
        private string $fromAddress = 'noreply@hilo.local',
    ) {}

    public function send(User $user, string $token): void
    {
        $resetUrl = \rtrim($this->adminUrl, '/') . '/#/reset-password?token=' . $token;

        $html = <<<HTML
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Réinitialisation de mot de passe</h2>
                <p>Bonjour {$this->escapeHtml($user->getUsername())},</p>
                <p>Vous avez demandé la réinitialisation de votre mot de passe. Cliquez sur le lien ci-dessous pour choisir un nouveau mot de passe :</p>
                <p style="margin: 30px 0;">
                    <a href="{$this->escapeHtml($resetUrl)}" style="background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                        Réinitialiser mon mot de passe
                    </a>
                </p>
                <p>Ce lien est valable pendant <strong>1 heure</strong>.</p>
                <p style="color: #666; font-size: 14px;">Si vous n'avez pas fait cette demande, vous pouvez ignorer cet email en toute sécurité.</p>
            </div>
            HTML;

        $email = (new Email())
            ->from($this->fromAddress)
            ->to($user->getEmail())
            ->subject('Réinitialisation de votre mot de passe')
            ->html($html);

        $this->mailer->send($email);
    }

    private function escapeHtml(string $value): string
    {
        return \htmlspecialchars($value, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
