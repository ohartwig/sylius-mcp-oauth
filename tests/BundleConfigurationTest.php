<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests;

use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\KohSyliusMcpOAuthBundle;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;

/**
 * THR-AGENT-014 and -020 were both configuration that was accepted and then
 * ignored. These tests pin that each setting reaches the service that must
 * act on it, and that an unusable value fails the container build instead of
 * being carried silently.
 */
#[CoversClass(KohSyliusMcpOAuthBundle::class)]
final class BundleConfigurationTest extends TestCase
{
    public function testDefaultsAreTheDocumentedOnes(): void
    {
        $config = $this->process([]);

        self::assertSame(3600, $config['access_token_ttl']);
        self::assertSame([], $config['allowed_redirect_uris']);
    }

    public function testATtlBelowAMinuteIsRefused(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['access_token_ttl' => 0]);
    }

    public function testAnUnusableAllowListEntryFailsTheBuild(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('is not a usable redirect URI');

        $this->process(['allowed_redirect_uris' => ['https://client.example/cb', 'http://attacker.example/cb']]);
    }

    public function testUsableAllowListEntriesAreKeptVerbatim(): void
    {
        $uris = ['https://claude.ai/api/mcp/auth_callback', 'http://127.0.0.1/callback', 'com.example.app:/cb'];

        self::assertSame($uris, $this->process(['allowed_redirect_uris' => $uris])['allowed_redirect_uris']);
    }

    public function testTheSettingsReachTheServicesThatEnforceThem(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $this->extension()->load([[
            'access_token_ttl' => 900,
            'allowed_redirect_uris' => ['https://client.example/cb'],
        ]], $container);

        self::assertSame(900, $container->getParameter('koh_mcp_oauth.access_token_ttl'));
        self::assertSame(['https://client.example/cb'], $container->getParameter('koh_mcp_oauth.allowed_redirect_uris'));

        $parameters = $container->getParameterBag();
        self::assertSame(
            900,
            $parameters->resolveValue($container->getDefinition(TokenController::class)->getArgument('$accessTokenTtl')),
        );
        self::assertSame(
            ['https://client.example/cb'],
            $parameters->resolveValue($container->getDefinition(RedirectUriPolicy::class)->getArgument(0)),
        );
    }

    /**
     * @param array<string, mixed> $config
     *
     * @return array<string, mixed>
     */
    private function process(array $config): array
    {
        $extension = $this->extension();
        self::assertInstanceOf(\Symfony\Component\DependencyInjection\Extension\ConfigurationExtensionInterface::class, $extension);
        $configuration = $extension->getConfiguration([], new ContainerBuilder());
        self::assertInstanceOf(ConfigurationInterface::class, $configuration);

        return (new Processor())->processConfiguration($configuration, [$config]);
    }

    private function extension(): ExtensionInterface
    {
        $extension = (new KohSyliusMcpOAuthBundle())->getContainerExtension();
        self::assertNotNull($extension);

        return $extension;
    }
}
