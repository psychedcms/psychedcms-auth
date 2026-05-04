<?php

declare(strict_types=1);

namespace PsychedCms\Auth\EventListener;

use Lexik\Bundle\JWTAuthenticationBundle\Event\AuthenticationSuccessEvent;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Sets an HttpOnly JWT cookie on successful login so the session
 * is shared across all subdomains (frontend, admin, API).
 */
final class SetJwtCookieOnLoginListener
{
    public function __construct(
        private readonly string $cookieDomain,
        private readonly string $appEnv,
    ) {}

    public function __invoke(AuthenticationSuccessEvent $event): void
    {
        $response = $event->getResponse();
        $data = $event->getData();

        if (!isset($data['token'])) {
            return;
        }

        $response->headers->setCookie(
            Cookie::create('jwt')
                ->withValue($data['token'])
                ->withExpires(time() + 3600)
                ->withPath('/')
                ->withDomain($this->cookieDomain)
                ->withSecure($this->appEnv !== 'test')
                ->withHttpOnly(true)
                ->withSameSite('lax')
        );
    }
}
