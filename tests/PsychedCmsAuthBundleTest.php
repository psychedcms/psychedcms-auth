<?php

declare(strict_types=1);

namespace PsychedCms\Auth\Tests;

use PHPUnit\Framework\TestCase;
use PsychedCms\Auth\PsychedCmsAuthBundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

final class PsychedCmsAuthBundleTest extends TestCase
{
    /**
     * Regression guard: gesdinet/jwt-refresh-token-bundle 2.x relies entirely
     * on a firewall with a `refresh_jwt` authenticator — there is no controller
     * behind /api/token/refresh. If this firewall is missing, the route falls
     * back to the unmapped routes.yaml entry and the API returns 404 to every
     * client (mobile, web, admin), looking like a transient session loss.
     *
     * This test runs prependExtension() and asserts the resulting security
     * config carries a `refresh_token` firewall with `refresh_jwt.check_path`
     * pointing at /api/token/refresh.
     */
    public function testPrependExtensionRegistersRefreshTokenFirewall(): void
    {
        $bundle = new PsychedCmsAuthBundle();
        $builder = new ContainerBuilder();
        $configurator = $this->createMinimalContainerConfigurator($builder);

        $bundle->prependExtension($configurator, $builder);

        $configs = $builder->getExtensionConfig('security');
        $this->assertNotEmpty($configs, 'PsychedCmsAuthBundle did not prepend any security config');

        $firewalls = [];
        foreach ($configs as $entry) {
            if (isset($entry['firewalls']) && \is_array($entry['firewalls'])) {
                $firewalls = array_merge($firewalls, $entry['firewalls']);
            }
        }

        $this->assertArrayHasKey(
            'refresh_token',
            $firewalls,
            'A `refresh_token` firewall must be registered or /api/token/refresh returns 404',
        );

        $refresh = $firewalls['refresh_token'];
        $this->assertTrue($refresh['stateless'] ?? false, '`refresh_token` firewall must be stateless');
        $this->assertArrayHasKey(
            'refresh_jwt',
            $refresh,
            'The refresh_token firewall must declare the `refresh_jwt` authenticator (gesdinet 2.x)',
        );
        $this->assertSame(
            '/api/token/refresh',
            $refresh['refresh_jwt']['check_path'] ?? null,
            'refresh_jwt.check_path must be /api/token/refresh',
        );
    }

    public function testRefreshTokenFirewallIsOrderedBeforeApiFirewall(): void
    {
        // Firewall order matters in Symfony — the first matching firewall
        // handles the request. The catch-all `api` firewall (pattern `^/api`)
        // would otherwise swallow `/api/token/refresh` and the refresh_jwt
        // authenticator would never run.
        $bundle = new PsychedCmsAuthBundle();
        $builder = new ContainerBuilder();
        $configurator = $this->createMinimalContainerConfigurator($builder);

        $bundle->prependExtension($configurator, $builder);

        foreach ($builder->getExtensionConfig('security') as $entry) {
            if (!isset($entry['firewalls'])) {
                continue;
            }
            $names = array_keys($entry['firewalls']);
            $refreshIdx = array_search('refresh_token', $names, true);
            $apiIdx = array_search('api', $names, true);
            if ($refreshIdx !== false && $apiIdx !== false) {
                $this->assertLessThan(
                    $apiIdx,
                    $refreshIdx,
                    '`refresh_token` firewall must be ordered before `api`',
                );
                return;
            }
        }
        $this->fail('Could not find both `refresh_token` and `api` firewalls in the same prepended config');
    }

    public function testPublicAuthFirewallNoLongerSwallowsTokenRefresh(): void
    {
        // Before the refresh_token firewall existed, `public_auth` advertised
        // `token/refresh` in its pattern with `security: false`. That made the
        // route reachable but auth-less, so the unmapped routes.yaml entry
        // still returned 404. Now that the dedicated firewall handles the
        // route, public_auth must NOT match it anymore.
        $bundle = new PsychedCmsAuthBundle();
        $builder = new ContainerBuilder();
        $configurator = $this->createMinimalContainerConfigurator($builder);

        $bundle->prependExtension($configurator, $builder);

        foreach ($builder->getExtensionConfig('security') as $entry) {
            if (!isset($entry['firewalls']['public_auth']['pattern'])) {
                continue;
            }
            $pattern = $entry['firewalls']['public_auth']['pattern'];
            $this->assertStringNotContainsString(
                'token/refresh',
                $pattern,
                'public_auth must no longer match /api/token/refresh — the dedicated refresh_token firewall handles it',
            );
            return;
        }
        $this->fail('public_auth firewall not found in prepended security config');
    }

    /**
     * The bundle's prependExtension takes a ContainerConfigurator, but only
     * ever calls methods on the ContainerBuilder. A minimal configurator is
     * enough to drive the method through.
     */
    private function createMinimalContainerConfigurator(ContainerBuilder $builder): ContainerConfigurator
    {
        $loader = new PhpFileLoader($builder, new \Symfony\Component\Config\FileLocator(__DIR__));
        $instanceof = [];

        return new ContainerConfigurator($builder, $loader, $instanceof, __DIR__, __FILE__);
    }
}
