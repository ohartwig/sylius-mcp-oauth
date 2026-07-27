<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use Koh\SyliusMcpOAuth\Controller\MetadataController;
use Koh\SyliusMcpOAuth\Controller\RegisterController;
use Koh\SyliusMcpOAuth\Controller\RevokeController;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * Route names are kept verbatim from the application this was extracted from.
 * Redirect URIs already issued to registered clients resolve through them, and
 * any generate() call elsewhere keeps working.
 *
 * /authorize deliberately sits under /admin so the admin firewall covers it:
 * consent requires a signed-in administrator. Everything else is public — a
 * client cannot authenticate before it has registered.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add('mcp_oauth_metadata_authorization_server', '/.well-known/oauth-authorization-server')
        ->controller([MetadataController::class, 'authorizationServer'])
        ->methods(['GET', 'HEAD']);

    $routes->add('mcp_oauth_metadata_protected_resource', '/.well-known/oauth-protected-resource')
        ->controller([MetadataController::class, 'protectedResource'])
        ->methods(['GET', 'HEAD']);

    $routes->add('mcp_oauth_register', '/mcp/oauth/register')
        ->controller(RegisterController::class)
        ->methods(['POST']);

    $routes->add('mcp_oauth_token', '/mcp/oauth/token')
        ->controller(TokenController::class)
        ->methods(['POST']);

    $routes->add('mcp_oauth_revoke', '/mcp/oauth/revoke')
        ->controller(RevokeController::class)
        ->methods(['POST']);

    // NOTE: /admin is the default Sylius admin path. If
    // SYLIUS_ADMIN_ROUTING_PATH_NAME is customised, override this route in the
    // application so it stays behind the admin firewall.
    $routes->add('mcp_oauth_authorize', '/admin/mcp/authorize')
        ->controller(AuthorizeController::class)
        ->methods(['GET', 'POST']);
};
