<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth;

use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * OAuth 2.1 authorization server for MCP clients.
 */
final class KohSyliusMcpOAuthBundle extends AbstractBundle
{
    protected string $extensionAlias = 'koh_mcp_oauth';

    /** config/ sits at the package root, not under src/. */
    public function getPath(): string
    {
        return \dirname(__DIR__);
    }

    /**
     * Registers the entity mapping so the application needs no doctrine.yaml edit.
     *
     * The entities carry explicit #[ORM\Table] names (app_mcp_access_token,
     * app_mcp_authorization_code, app_mcp_oauth_client). They moved here from an
     * application namespace, and keeping the table names verbatim is what makes
     * that a pure code move: no schema change, no migration, and existing rows —
     * live tokens included — keep working. `doctrine:schema:validate --skip-sync`
     * is the check that this still holds.
     */
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->prependExtensionConfig('doctrine', [
            'orm' => [
                'mappings' => [
                    'KohSyliusMcpOAuth' => [
                        'type' => 'attribute',
                        'is_bundle' => false,
                        'dir' => \dirname(__DIR__).'/src/Entity',
                        'prefix' => 'Koh\\SyliusMcpOAuth\\Entity',
                        'alias' => 'KohMcpOAuth',
                    ],
                ],
            ],
        ]);
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('resource_path')
                    ->defaultValue('/_mcp')
                    ->info('Path of the protected MCP endpoint, as advertised in the RFC 9728 metadata.')
                ->end()
                ->integerNode('access_token_ttl')
                    ->defaultValue(3600)
                    ->info('Access token lifetime in seconds.')
                ->end()
                ->arrayNode('allowed_redirect_uris')
                    ->info('HTTPS redirect URIs accepted at registration in addition to loopback (RFC 8252).')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
            ->end();
    }

    /**
     * @param array<mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->setParameter('koh_mcp_oauth.resource_path', (string) ($config['resource_path'] ?? '/_mcp'));
        $builder->setParameter('koh_mcp_oauth.access_token_ttl', (int) ($config['access_token_ttl'] ?? 3600));
        $builder->setParameter('koh_mcp_oauth.allowed_redirect_uris', $config['allowed_redirect_uris'] ?? []);

        $container->import('../config/services.php');
    }
}
