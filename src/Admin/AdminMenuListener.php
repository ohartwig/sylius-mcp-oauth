<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Admin;

use Sylius\Bundle\UiBundle\Menu\Event\MenuBuilderEvent;

/**
 * Puts "MCP tokens" into the admin sidebar, under Configuration.
 */
final class AdminMenuListener
{
    public function __construct(
        private readonly bool $enabled = true,
    ) {
    }

    public function __invoke(MenuBuilderEvent $event): void
    {
        if (!$this->enabled) {
            return;
        }

        $parent = $event->getMenu()->getChild('configuration') ?? $event->getMenu();

        $parent
            ->addChild('koh_mcp_tokens', ['route' => 'mcp_oauth_admin_tokens'])
            ->setLabel('koh_mcp_oauth.admin.tokens.menu')
            ->setLabelAttribute('icon', 'tabler:key');
    }
}
