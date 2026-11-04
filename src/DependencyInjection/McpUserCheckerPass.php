<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\DependencyInjection;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Puts Sylius's EnabledUserChecker into the `mcp` firewall's checker chain.
 *
 * Sylius tags `sylius.user_checker.enabled` for its own firewalls only (admin,
 * api_admin, api_shop). A firewall that declares
 * `user_checker: security.user_checker.chain.mcp` collects the services tagged
 * `security.user_checker.mcp`; tagging it here means an installer cannot
 * forget it (AUD-011-F01). The authenticator checks the account itself as
 * well ({@see \Koh\SyliusMcpOAuth\Security\AccountStatusGuard}), so a firewall
 * without the line is still covered.
 */
final class McpUserCheckerPass implements CompilerPassInterface
{
    public const SYLIUS_ENABLED_CHECKER = 'sylius.user_checker.enabled';

    public const FIREWALL_TAG = 'security.user_checker.mcp';

    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(self::SYLIUS_ENABLED_CHECKER)) {
            return;
        }

        $definition = $container->getDefinition(self::SYLIUS_ENABLED_CHECKER);
        if (!$definition->hasTag(self::FIREWALL_TAG)) {
            $definition->addTag(self::FIREWALL_TAG, ['priority' => 100]);
        }
    }
}
