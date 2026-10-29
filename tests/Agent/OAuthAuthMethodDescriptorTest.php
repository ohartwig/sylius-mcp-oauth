<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Agent;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusMcpOAuth\Agent\OAuthAuthMethodDescriptor;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\ChannelInterface;

/**
 * /auth.md and the agent_auth block print this text. AUD-068-F01 was a rate
 * limit the document promised and the shop did not enforce, so the limits
 * here come from the same configuration the limiter reads, and a limit that
 * is switched off is not mentioned at all.
 */
#[CoversClass(OAuthAuthMethodDescriptor::class)]
final class OAuthAuthMethodDescriptorTest extends TestCase
{
    public function testTheDocumentStatesTheConfiguredLimits(): void
    {
        $documentation = $this->documentation([
            'register' => ['limit' => 10, 'interval' => '1 hour'],
            'token' => ['limit' => 30, 'interval' => '1 minute'],
            'mcp' => ['limit' => 300, 'interval' => '1 minute'],
        ]);

        self::assertStringContainsString('### Rate limits', $documentation);
        self::assertStringContainsString('`https://shop.example/_mcp`: 300 requests per 1 minute per credential', $documentation);
        self::assertStringContainsString('Token endpoint: 30 requests per 1 minute per client address', $documentation);
        self::assertStringContainsString('Registration: 10 requests per 1 hour per client address', $documentation);
        self::assertStringContainsString('`429` with `Retry-After`', $documentation);
    }

    public function testALimitThatIsOffIsNotPromised(): void
    {
        $documentation = $this->documentation([
            'register' => ['limit' => 10, 'interval' => '1 hour'],
            'token' => ['limit' => 30, 'interval' => '1 minute'],
            'mcp' => ['limit' => 0, 'interval' => '1 minute'],
        ]);

        self::assertStringNotContainsString('per credential', $documentation);
        self::assertStringContainsString('per client address', $documentation);
    }

    public function testWithoutAnyLimitThereIsNoRateLimitSection(): void
    {
        self::assertStringNotContainsString('Rate limits', $this->documentation([]));
    }

    public function testTheMcpLineFollowsTheConfiguredResourcePath(): void
    {
        $documentation = $this->documentation(['mcp' => ['limit' => 5, 'interval' => '1 second']], '/agents/mcp');

        self::assertStringContainsString('`https://shop.example/agents/mcp`: 5 requests per 1 second per credential', $documentation);
    }

    /** @param array<string, array{limit?: int, interval?: string}> $limits */
    private function documentation(array $limits, string $resourcePath = '/_mcp'): string
    {
        $context = new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US');

        return (new OAuthAuthMethodDescriptor($limits, $resourcePath))->getAuthMethodDescriptor($context)->documentation;
    }
}
