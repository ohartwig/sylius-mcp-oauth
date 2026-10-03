<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\ChannelInterface;
use Symfony\Component\HttpFoundation\Request;

final class ResourceIndicatorTest extends TestCase
{
    public function testTheCanonicalResourceIsTheMcpEndpointOfTheChannel(): void
    {
        self::assertSame('https://shop.example/_mcp', $this->indicator()->canonical());
    }

    /** RFC 3986 §6.2.2.1: scheme and host compare case-insensitively; a trailing slash is not a different resource. */
    public function testEquivalentSpellingsMatch(): void
    {
        self::assertTrue($this->indicator()->matches('https://SHOP.example/_mcp/'));
        self::assertTrue($this->indicator()->matches('HTTPS://shop.example/_mcp'));
    }

    public function testOtherResourcesDoNotMatch(): void
    {
        $indicator = $this->indicator();

        self::assertFalse($indicator->matches('https://shop.example/_mcp/other'));
        self::assertFalse($indicator->matches('https://evil.example/_mcp'));
        self::assertFalse($indicator->matches('http://shop.example/_mcp'));
        self::assertFalse($indicator->matches('not a url'));
    }

    /** Without a channel the request decides; without either, nothing matches. */
    public function testTheRequestIsTheFallback(): void
    {
        $factory = $this->createStub(AgentContextFactoryInterface::class);
        $factory->method('create')->willThrowException(new \RuntimeException('no channel'));
        $indicator = new ResourceIndicator($factory);

        self::assertSame('https://host.example/_mcp', $indicator->canonical(Request::create('https://host.example/anything')));
        self::assertNull($indicator->canonical());
        self::assertFalse($indicator->matches('https://host.example/_mcp'));
    }

    private function indicator(): ResourceIndicator
    {
        $factory = $this->createStub(AgentContextFactoryInterface::class);
        $factory->method('create')->willReturn(new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US'));

        return new ResourceIndicator($factory, '/_mcp');
    }
}
