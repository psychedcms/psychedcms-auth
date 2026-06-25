<?php

declare(strict_types=1);

namespace PsychedCms\Auth;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class PsychedCmsAuthBundle extends AbstractBundle
{
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->arrayNode('permissions')
                    ->info('Permissions contributed by other bundles via prependExtensionConfig, grouped by group name. Format: { group: [permission1, permission2] }')
                    ->useAttributeAsKey('group')
                    ->normalizeKeys(false)
                    ->arrayPrototype()
                        ->scalarPrototype()->end()
                    ->end()
                ->end()
            ->end();
    }

    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        // Register Doctrine ORM mapping for the User entity
        $builder->prependExtensionConfig('doctrine', [
            'orm' => [
                'mappings' => [
                    'PsychedCmsAuth' => [
                        'is_bundle' => false,
                        'type' => 'attribute',
                        'dir' => \dirname(__DIR__) . '/src/Entity',
                        'prefix' => 'PsychedCms\Auth\Entity',
                        'alias' => 'PsychedCmsAuth',
                    ],
                ],
            ],
        ]);

        // Prepend security configuration
        $builder->prependExtensionConfig('security', [
            'password_hashers' => [
                'Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface' => [
                    'algorithm' => 'auto',
                ],
            ],
            'providers' => [
                'psychedcms_user_provider' => [
                    'entity' => [
                        'class' => 'PsychedCms\Auth\Entity\User',
                        'property' => 'email',
                    ],
                ],
            ],
            'firewalls' => [
                // The refresh firewall MUST come before any catch-all `^/api`
                // firewall, otherwise the latter intercepts the request first
                // and the refresh-jwt authenticator never runs (route is
                // declared in routes.yaml but has no controller — gesdinet
                // 2.x relies entirely on the firewall authenticator).
                'refresh_token' => [
                    'pattern' => '^/api/token/refresh$',
                    'stateless' => true,
                    'refresh_jwt' => [
                        'check_path' => '/api/token/refresh',
                    ],
                ],
                'public_auth' => [
                    'pattern' => '^/api/(health|register|forgot-password|reset-password|accept-invitation|verify-email|logout)',
                    'stateless' => true,
                    'security' => false,
                ],
                // Harden the MCP HTTP transport (/_mcp). MUST come before the
                // catch-all `api` firewall. Accepts either a JWT (a delegated
                // editor token carrying act_as_agent, or a normal user JWT) or
                // the static SERVICE_TOKEN via ServiceTokenAuthenticator (Bearer
                // non-JWT -> system user ROLE_ADMIN).
                'mcp' => [
                    'pattern' => '^/_mcp',
                    'stateless' => true,
                    'jwt' => [],
                    'custom_authenticators' => ['PsychedCms\\Auth\\Security\\ServiceTokenAuthenticator'],
                    'entry_point' => 'jwt',
                ],
                'api' => [
                    'pattern' => '^/api',
                    'stateless' => true,
                    'json_login' => [
                        'check_path' => '/api/login',
                        'username_path' => 'email',
                        'password_path' => 'password',
                        'success_handler' => 'lexik_jwt_authentication.handler.authentication_success',
                        'failure_handler' => 'lexik_jwt_authentication.handler.authentication_failure',
                    ],
                    'jwt' => [],
                    'custom_authenticators' => ['PsychedCms\Auth\Security\ServiceTokenAuthenticator'],
                    'entry_point' => 'jwt',
                ],
            ],
        ]);

        if ($builder->hasExtension('framework')) {
            $loader = new YamlFileLoader($builder, new FileLocator($this->getPath() . '/config'));
            $loader->load('rate_limiter.yaml');
        }
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import('../config/services.yaml');

        $builder->setParameter('psyched_cms_auth.permissions', $config['permissions'] ?? []);
    }
}
