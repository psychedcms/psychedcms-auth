<?php

declare(strict_types=1);

namespace PsychedCms\Auth;

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
                        'property' => 'username',
                    ],
                ],
            ],
            'firewalls' => [
                'login' => [
                    'pattern' => '^/api/login',
                    'stateless' => true,
                    'login_throttling' => [
                        'max_attempts' => 5,
                        'interval' => '15 minutes',
                    ],
                    'json_login' => [
                        'check_path' => '/api/login',
                        'success_handler' => 'lexik_jwt_authentication.handler.authentication_success',
                        'failure_handler' => 'lexik_jwt_authentication.handler.authentication_failure',
                    ],
                ],
                'api' => [
                    'pattern' => '^/api',
                    'stateless' => true,
                    'jwt' => [],
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
    }
}
