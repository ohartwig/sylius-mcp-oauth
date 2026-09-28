<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Agent;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusMcpOAuth\Agent\OAuthEndpointProvider;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\ChannelInterface;

final class OAuthEndpointProviderTest extends TestCase
{
    public function testBothMetadataDocumentsAreAnnounced(): void
    {
        $paths = array_map(
            static fn ($e): string => $e->path,
            iterator_to_array((new OAuthEndpointProvider())->getAgentEndpoints($this->context())),
        );

        self::assertSame([
            '/.well-known/oauth-authorization-server',
            '/.well-known/oauth-protected-resource',
        ], $paths);
    }

    /**
     * The catalog anchors on the resource that is actually protected, not on
     * the metadata describing it — an agent follows the anchor to call the API.
     */
    public function testCatalogEntryAnchorsOnTheProtectedResource(): void
    {
        $entries = iterator_to_array((new OAuthEndpointProvider())->getApiCatalogEntries($this->context()));

        self::assertCount(1, $entries);
        self::assertSame('https://shop.example.com/_mcp', $entries[0]->anchor);
        self::assertSame(
            'https://shop.example.com/.well-known/oauth-protected-resource',
            $entries[0]->serviceDesc[0]->href,
        );
        self::assertSame('https://shop.example.com/auth.md', $entries[0]->serviceDoc[0]->href);
    }

    /** A shop that moved the MCP endpoint must not advertise the default path. */
    public function testResourcePathIsConfigurable(): void
    {
        $entries = iterator_to_array(
            (new OAuthEndpointProvider('/api/mcp'))->getApiCatalogEntries($this->context()),
        );

        self::assertSame('https://shop.example.com/api/mcp', $entries[0]->anchor);
    }

    public function testCatalogEntryIsSerialisableForTheLinkset(): void
    {
        $entry = iterator_to_array((new OAuthEndpointProvider())->getApiCatalogEntries($this->context()))[0];

        $array = $entry->toArray();

        self::assertSame('https://shop.example.com/_mcp', $array['anchor']);
        self::assertSame('application/json', $array['service-desc'][0]['type']);
        self::assertSame('text/markdown', $array['service-doc'][0]['type']);
    }

    private function context(): AgentContext
    {
        $channel = $this->createMock(ChannelInterface::class);
        $channel->method('getCode')->willReturn('WEB_DE');

        return new AgentContext($channel, 'https://shop.example.com', 'de_DE', ['de_DE']);
    }
}
