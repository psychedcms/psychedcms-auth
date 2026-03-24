<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Service;

use PsychedCms\Auth\Entity\User;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

final readonly class InvitationMailer
{
    public function __construct(
        private MailerInterface $mailer,
        private string $adminUrl,
        private string $frontendUrl,
        private string $fromAddress = 'noreply@hilo.local',
    ) {}

    public function sendInvitation(User $user, string $token): void
    {
        $roles = $user->getRoles();
        $isAdminOrEditor = \in_array('ROLE_ADMIN', $roles, true) || \in_array('ROLE_EDITOR', $roles, true);

        if ($isAdminOrEditor) {
            $url = \rtrim($this->adminUrl, '/') . '/#/set-password?token=' . $token;
        } else {
            $url = \rtrim($this->frontendUrl, '/') . '/set-password?token=' . $token;
        }

        $html = <<<HTML
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Bienvenue sur Hilo</h2>
                <p>Bonjour {$this->escapeHtml($user->getUsername())},</p>
                <p>Vous avez été invité(e) à rejoindre Hilo. Cliquez sur le lien ci-dessous pour définir votre mot de passe :</p>
                <p style="margin: 30px 0;">
                    <a href="{$this->escapeHtml($url)}" style="background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                        Définir mon mot de passe
                    </a>
                </p>
                <p>Ce lien est valable pendant <strong>24 heures</strong>.</p>
                <p style="color: #666; font-size: 14px;">Si vous n'attendiez pas cette invitation, vous pouvez ignorer cet email en toute sécurité.</p>
            </div>
            HTML;

        $email = (new Email())
            ->from($this->fromAddress)
            ->to($user->getEmail())
            ->subject('Vous avez été invité(e) sur Hilo')
            ->html($html);

        $this->mailer->send($email);
    }

    public function sendVerification(User $user, string $token): void
    {
        $url = \rtrim($this->frontendUrl, '/') . '/verify-email?token=' . $token;

        $html = <<<HTML
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2>Vérifiez votre adresse email</h2>
                <p>Bonjour {$this->escapeHtml($user->getUsername())},</p>
                <p>Merci de vous être inscrit(e) sur Hilo. Cliquez sur le lien ci-dessous pour vérifier votre adresse email :</p>
                <p style="margin: 30px 0;">
                    <a href="{$this->escapeHtml($url)}" style="background-color: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                        Vérifier mon email
                    </a>
                </p>
                <p>Ce lien est valable pendant <strong>24 heures</strong>.</p>
                <p style="color: #666; font-size: 14px;">Si vous n'avez pas créé de compte, vous pouvez ignorer cet email en toute sécurité.</p>
            </div>
            HTML;

        $email = (new Email())
            ->from($this->fromAddress)
            ->to($user->getEmail())
            ->subject('Vérifiez votre adresse email')
            ->html($html);

        $this->mailer->send($email);
    }

    private function escapeHtml(string $value): string
    {
        return \htmlspecialchars($value, \ENT_QUOTES | \ENT_SUBSTITUTE, 'UTF-8');
    }
}
