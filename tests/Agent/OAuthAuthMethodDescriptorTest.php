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

    /** The prose follows AUTH.md: register, claim, poll, exchange — with this shop's URLs. */
    public function testWithAgentRegistrationTheDocumentWalksTheAuthMdSteps(): void
    {
        $documentation = $this->documentation(['identity' => ['limit' => 10, 'interval' => '1 hour']], agentRegistration: true);

        self::assertStringContainsString('### Agent registration (auth.md)', $documentation);
        self::assertStringContainsString('POST https://shop.example/mcp/oauth/agent/identity', $documentation);
        self::assertStringContainsString('POST https://shop.example/mcp/oauth/agent/identity/claim', $documentation);
        self::assertStringContainsString('grant_type=urn:workos:agent-auth:grant-type:claim&claim_token=clm_...', $documentation);
        self::assertStringContainsString('grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<identity_assertion>', $documentation);
        self::assertStringContainsString('scope `mcp:read`', $documentation);
        self::assertStringContainsString("claim window\nis 30 minutes", $documentation);
        self::assertStringContainsString('- Agent registration and claim: 10 requests per 1 hour per client address.', $documentation);
        self::assertLessThan(strpos($documentation, '### OAuth clients (MCP)'), strpos($documentation, '### Agent registration'));
    }

    public function testTheSectionsAreSeparatedAsMarkdownBlocks(): void
    {
        $documentation = $this->documentation(['token' => ['limit' => 1, 'interval' => '1 minute']], agentRegistration: true);

        self::assertStringContainsString("endpoints and the `agent_auth` block.\n\n### Agent registration (auth.md)\n", $documentation);
        self::assertStringContainsString("The\n`events_endpoint` of the profile is not offered.\n\n### OAuth clients (MCP)\n", $documentation);
        self::assertStringContainsString("/mcp/oauth/revoke\n\n### Rate limits\n", $documentation);
        self::assertStringContainsString("endpoints and the `agent_auth` block.\n\n### OAuth clients (MCP)\n", $this->documentation([]));
    }

    /** By default claiming grants `mcp` and the window is an hour, as the bundle configures. */
    public function testTheDefaultsMatchTheBundleDefaults(): void
    {
        $context = new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US');
        $documentation = (new OAuthAuthMethodDescriptor(agentRegistration: true))->getAuthMethodDescriptor($context)->documentation;

        self::assertStringContainsString('scope `mcp`', $documentation);
        self::assertStringContainsString("claim window\nis 60 minutes", $documentation);
    }

    public function testWithoutAgentRegistrationItIsNeitherDescribedNorLimited(): void
    {
        $documentation = $this->documentation(['identity' => ['limit' => 10, 'interval' => '1 hour']]);

        self::assertStringNotContainsString('Agent registration', $documentation);
        self::assertStringNotContainsString('agent/identity', $documentation);
        self::assertStringContainsString('### OAuth clients (MCP)', $documentation);
    }

    public function testTheDescriptorDeclaresOnlyWhatIsServed(): void
    {
        $context = new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US');

        $on = (new OAuthAuthMethodDescriptor(agentRegistration: true))->getAuthMethodDescriptor($context);
        self::assertSame('oauth2', $on->id);
        self::assertSame('https://shop.example/auth.md', $on->skillUri);
        self::assertSame(['anonymous', 'service_auth'], $on->identityTypes);
        self::assertSame('https://shop.example/mcp/oauth/agent/identity', $on->identityEndpoint);
        self::assertSame('https://shop.example/mcp/oauth/agent/identity/claim', $on->claimEndpoint);
        self::assertNull($on->eventsEndpoint);
        self::assertSame([], $on->assertionTypes);

        $off = (new OAuthAuthMethodDescriptor())->getAuthMethodDescriptor($context);
        self::assertSame([], $off->identityTypes);
        self::assertNull($off->identityEndpoint);
        self::assertNull($off->claimEndpoint);
    }

    /** @param array<string, array{limit?: int, interval?: string}> $limits */
    private function documentation(array $limits, string $resourcePath = '/_mcp', bool $agentRegistration = false): string
    {
        $context = new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US');

        return (new OAuthAuthMethodDescriptor($limits, $resourcePath, $agentRegistration, ['mcp:read'], 1800))->getAuthMethodDescriptor($context)->documentation;
    }
}
