<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusAgentContracts\Http\AgentJsonResponder;
use Koh\SyliusAgentContracts\Registry\AuthMethodRegistry;
use Koh\SyliusMcpOAuth\Admin\AdminMenuListener;
use Koh\SyliusMcpOAuth\Admin\TokenAdminController;
use Koh\SyliusMcpOAuth\Agent\OAuthAuthMethodDescriptor;
use Koh\SyliusMcpOAuth\Agent\OAuthEndpointProvider;
use Koh\SyliusMcpOAuth\Command\CreateMcpTokenCommand;
use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use Koh\SyliusMcpOAuth\Controller\MetadataController;
use Koh\SyliusMcpOAuth\Controller\RegisterController;
use Koh\SyliusMcpOAuth\Controller\RevokeController;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiterFactory;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator;
use Sylius\Bundle\UiBundle\Menu\Event\MenuBuilderEvent;
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
    $services->set(RefreshTokenManager::class)->public();

    $services->set(ResourceIndicator::class)
        ->args([
            service(AgentContextFactoryInterface::class)->nullOnInvalid(),
            param('koh_mcp_oauth.resource_path'),
        ]);

    $services->set(CorsPolicy::class)
        ->args([param('koh_mcp_oauth.cors_allowed_origins')]);

    // One limiter per endpoint (register, token, mcp), on the application cache. Built here rather
    // than through framework.rate_limiter so the application needs no
    // configuration for it.
    $services->set(EndpointRateLimiter::class)
        ->factory([EndpointRateLimiterFactory::class, 'create'])
        ->args([
            param('koh_mcp_oauth.rate_limits'),
            service('cache.app'),
        ]);

    // Referenced by name in the application's security.yaml.
    $services->set(McpAccessTokenAuthenticator::class)
        ->arg('$resource', service(ResourceIndicator::class))
        ->arg('$rateLimiter', service(EndpointRateLimiter::class))
        ->public();

    $services->set(CreateMcpTokenCommand::class)->tag('console.command');

    $services->set(MetadataController::class)
        ->args([
            service(AgentContextFactoryInterface::class),
            service(AuthMethodRegistry::class),
            service(AgentJsonResponder::class),
            param('koh_mcp_oauth.resource_path'),
            param('koh_mcp_oauth.refresh_tokens_enabled'),
        ])
        ->public()
        ->tag('controller.service_arguments');

    $services->set(TokenController::class)
        ->arg('$accessTokenTtl', param('koh_mcp_oauth.access_token_ttl'))
        ->arg('$refreshTokenTtl', param('koh_mcp_oauth.refresh_token_ttl'))
        ->arg('$refreshTokens', service(RefreshTokenManager::class))
        ->arg('$resource', service(ResourceIndicator::class))
        ->arg('$rateLimiter', service(EndpointRateLimiter::class))
        ->arg('$corsPolicy', service(CorsPolicy::class))
        ->public()
        ->tag('controller.service_arguments');

    $services->set(AuthorizeController::class)
        ->arg('$resource', service(ResourceIndicator::class))
        ->arg('$defaultScopes', param('koh_mcp_oauth.default_scopes'))
        ->public()
        ->tag('controller.service_arguments');

    $services->set(RegisterController::class)
        ->arg('$rateLimiter', service(EndpointRateLimiter::class))
        ->arg('$corsPolicy', service(CorsPolicy::class))
        ->public()
        ->tag('controller.service_arguments');

    $services->set(RevokeController::class)
        ->arg('$refreshTokens', service(RefreshTokenManager::class))
        ->arg('$corsPolicy', service(CorsPolicy::class))
        ->public()
        ->tag('controller.service_arguments');

    $services->set(TokenAdminController::class)
        ->args([
            service(AccessTokenManager::class),
            service(OAuthServer::class),
            service('sylius.repository.admin_user'),
            service(RefreshTokenManager::class),
            param('koh_mcp_oauth.admin.overview_role'),
        ])
        ->public()
        ->tag('controller.service_arguments');

    if (class_exists(MenuBuilderEvent::class)) {
        $services->set(AdminMenuListener::class)
            ->args([param('koh_mcp_oauth.admin.menu')])
            ->tag('kernel.event_listener', ['event' => 'sylius.menu.admin.main']);
    }

    $services->set(OAuthAuthMethodDescriptor::class)
        ->args([param('koh_mcp_oauth.rate_limits'), param('koh_mcp_oauth.resource_path')])
        ->tag('koh_agent.auth_method');

    $services->set(OAuthEndpointProvider::class)
        ->args([param('koh_mcp_oauth.resource_path')])
        ->tag('koh_agent.endpoint')
        ->tag('koh_agent.api_catalog_entry');
};
