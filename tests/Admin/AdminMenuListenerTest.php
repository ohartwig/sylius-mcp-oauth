<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Admin;

use Knp\Menu\MenuFactory;
use Koh\SyliusMcpOAuth\Admin\AdminMenuListener;
use PHPUnit\Framework\TestCase;
use Sylius\Bundle\UiBundle\Menu\Event\MenuBuilderEvent;

final class AdminMenuListenerTest extends TestCase
{
    public function testTheEntryGoesUnderConfiguration(): void
    {
        $factory = new MenuFactory();
        $menu = $factory->createItem('root');
        $menu->addChild('configuration');

        (new AdminMenuListener())(new MenuBuilderEvent($factory, $menu));

        $item = $menu->getChild('configuration')?->getChild('koh_mcp_tokens');
        self::assertNotNull($item);
        self::assertSame('koh_mcp_oauth.admin.tokens.menu', $item->getLabel());
    }

    /** Without a Configuration section the entry still appears, at the top level. */
    public function testWithoutConfigurationItGoesToTheRoot(): void
    {
        $factory = new MenuFactory();
        $menu = $factory->createItem('root');

        (new AdminMenuListener())(new MenuBuilderEvent($factory, $menu));

        self::assertNotNull($menu->getChild('koh_mcp_tokens'));
    }

    /** An application with its own token page switches the entry off. */
    public function testItCanBeSwitchedOff(): void
    {
        $factory = new MenuFactory();
        $menu = $factory->createItem('root');
        $menu->addChild('configuration');

        (new AdminMenuListener(false))(new MenuBuilderEvent($factory, $menu));

        self::assertNull($menu->getChild('configuration')?->getChild('koh_mcp_tokens'));
    }
}
