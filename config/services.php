<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusAgentContracts\Http\AgentJsonResponder;
use Koh\SyliusAgentContracts\Registry\AuthMethodRegistry;
use Koh\SyliusMcpOAuth\Agent\OAuthAuthMethodDescriptor;
use Koh\SyliusMcpOAuth\Agent\OAuthEndpointProvider;
use Koh\SyliusMcpOAuth\Command\CreateMcpTokenCommand;
use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use Koh\SyliusMcpOAuth\Controller\MetadataController;
use Koh\SyliusMcpOAuth\Controller\RegisterController;
use Koh\SyliusMcpOAuth\Controller\RevokeController;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure();

    $services->set(RedirectUriPolicy::class)
        ->args([param('koh_mcp_oauth.allowed_redirect_uris')]);

    $services->set(OAuthServer::class)->public();
    $services->set(AccessTokenManager::class)->public();

    // Referenced by name in the application's security.yaml.
    $services->set(McpAccessTokenAuthenticator::class)->public();

    $services->set(CreateMcpTokenCommand::class)->tag('console.command');

    $services->set(MetadataController::class)
        ->args([
            service(AgentContextFactoryInterface::class),
            service(AuthMethodRegistry::class),
            service(AgentJsonResponder::class),
            param('koh_mcp_oauth.resource_path'),
        ])
        ->public()
        ->tag('controller.service_arguments');

    $services->set(TokenController::class)
        ->arg('$accessTokenTtl', param('koh_mcp_oauth.access_token_ttl'))
        ->public()
        ->tag('controller.service_arguments');

    foreach ([AuthorizeController::class, RegisterController::class, RevokeController::class] as $controller) {
        $services->set($controller)
            ->public()
            ->tag('controller.service_arguments');
    }

    $services->set(OAuthAuthMethodDescriptor::class)
        ->tag('koh_agent.auth_method');

    $services->set(OAuthEndpointProvider::class)
        ->args([param('koh_mcp_oauth.resource_path')])
        ->tag('koh_agent.endpoint')
        ->tag('koh_agent.api_catalog_entry');
};
