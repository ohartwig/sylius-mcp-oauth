<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests;

use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
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
        self::assertSame(1209600, $config['refresh_token_ttl']);
        self::assertSame(['mcp'], $config['default_scopes']);
        self::assertSame([], $config['cors_allowed_origins'], 'no browser origin is trusted by default');
        self::assertSame(['limit' => 10, 'interval' => '1 hour'], $config['rate_limits']['register']);
        self::assertSame(['limit' => 30, 'interval' => '1 minute'], $config['rate_limits']['token']);
        self::assertSame(['limit' => 300, 'interval' => '1 minute'], $config['rate_limits']['mcp'], 'the MCP endpoint is limited per credential out of the box');
        self::assertSame(['limit' => 10, 'interval' => '1 hour'], $config['rate_limits']['identity']);
        self::assertSame(['enabled' => true, 'claim_ttl' => 3600, 'assertion_ttl' => 86400], $config['agent_registration']);
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function outOfRange(): iterable
    {
        yield 'claim window beyond a day' => [['agent_registration' => ['claim_ttl' => 86401]]];
        yield 'claim window under ten minutes' => [['agent_registration' => ['claim_ttl' => 599]]];
        yield 'assertion beyond thirty days' => [['agent_registration' => ['assertion_ttl' => 2592001]]];
        yield 'assertion under ten minutes' => [['agent_registration' => ['assertion_ttl' => 599]]];
        yield 'negative identity limit' => [['rate_limits' => ['identity' => ['limit' => -1]]]];
    }

    /** @param array<string, mixed> $config */
    #[\PHPUnit\Framework\Attributes\DataProvider('outOfRange')]
    public function testAgentRegistrationBoundsAreEnforced(array $config): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process($config);
    }

    public function testTheBoundsThemselvesAreAccepted(): void
    {
        $low = $this->process(['agent_registration' => ['claim_ttl' => 600, 'assertion_ttl' => 600], 'rate_limits' => ['identity' => ['limit' => 0]]]);
        $high = $this->process(['agent_registration' => ['claim_ttl' => 86400, 'assertion_ttl' => 2592000]]);

        self::assertSame([600, 600, 0], [$low['agent_registration']['claim_ttl'], $low['agent_registration']['assertion_ttl'], $low['rate_limits']['identity']['limit']]);
        self::assertSame([86400, 2592000], [$high['agent_registration']['claim_ttl'], $high['agent_registration']['assertion_ttl']]);
    }

    public function testAgentRegistrationIsOnByDefault(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $this->extension()->load([[]], $container);

        self::assertTrue($container->getParameter('koh_mcp_oauth.agent_registration.enabled'));
        self::assertSame(3600, $container->getParameter('koh_mcp_oauth.agent_registration.claim_ttl'));
        self::assertSame(86400, $container->getParameter('koh_mcp_oauth.agent_registration.assertion_ttl'));
    }

    public function testTheAgentRegistrationSettingsReachTheirServices(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $this->extension()->load([['agent_registration' => ['enabled' => false, 'claim_ttl' => 900, 'assertion_ttl' => 7200]]], $container);

        self::assertFalse($container->getParameter('koh_mcp_oauth.agent_registration.enabled'));
        self::assertSame(900, $container->getParameter('koh_mcp_oauth.agent_registration.claim_ttl'));
        self::assertSame(7200, $container->getParameter('koh_mcp_oauth.agent_registration.assertion_ttl'));
        $parameters = $container->getParameterBag();
        self::assertFalse($parameters->resolveValue($container->getDefinition(TokenController::class)->getArgument('$agentRegistrationEnabled')));
        self::assertSame([900, 7200], [
            $parameters->resolveValue($container->getDefinition(AgentRegistrationManager::class)->getArgument(3)),
            $parameters->resolveValue($container->getDefinition(AgentRegistrationManager::class)->getArgument(4)),
        ]);
    }

    public function testAnUnknownDefaultScopeFailsTheBuild(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process(['default_scopes' => ['admin']]);
    }

    /** The bundle's own migrations are found without a doctrine_migrations.yaml edit. */
    public function testTheMigrationsPathIsPrepended(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter('kernel.environment', 'test');
        $container->setParameter('kernel.build_dir', sys_get_temp_dir());
        $container->registerExtension(new class extends \Symfony\Component\DependencyInjection\Extension\Extension {
            public function load(array $configs, ContainerBuilder $container): void
            {
            }

            public function getAlias(): string
            {
                return 'doctrine_migrations';
            }
        });
        $container->registerExtension(new class extends \Symfony\Component\DependencyInjection\Extension\Extension {
            public function load(array $configs, ContainerBuilder $container): void
            {
            }

            public function getAlias(): string
            {
                return 'doctrine';
            }
        });
        $extension = $this->extension();
        self::assertInstanceOf(\Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface::class, $extension);
        $extension->prepend($container);

        $paths = $container->getExtensionConfig('doctrine_migrations')[0]['migrations_paths'] ?? [];
        self::assertArrayHasKey('Koh\\SyliusMcpOAuth\\Migrations', $paths);
        self::assertDirectoryExists($paths['Koh\\SyliusMcpOAuth\\Migrations']);
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
