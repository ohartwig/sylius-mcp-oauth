<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Template;

use Koh\SyliusMcpOAuth\Admin\TokenAdminController;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Symfony\Component\Translation\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\ChainLoader;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

/**
 * The token overview rendered with real Twig and the shipped catalogues. The
 * Sylius admin layout is replaced by a one-block stand-in: what is tested is
 * this template, not Sylius'.
 */
#[CoversNothing]
final class TokenAdminTemplateTest extends TestCase
{
    private const ROOT = __DIR__.'/../..';

    public function testActiveTokensCarryARevokeFormWithCsrf(): void
    {
        $html = $this->render('en');

        self::assertStringContainsString('MCP access tokens', $html);
        self::assertStringContainsString('admin@example.test', $html);
        self::assertStringContainsString('action="/admin/mcp/access-tokens/5/revoke"', $html);
        self::assertStringContainsString('name="_token" value="csrf-for-mcp_token_revoke_5"', $html);
        self::assertStringContainsString('198.51.100.4', $html);
        self::assertStringContainsString('<code>mcp:read</code>', $html);
    }

    public function testTheGermanCatalogueIsComplete(): void
    {
        $html = $this->render('de');

        self::assertStringContainsString('MCP-Zugriffstokens', $html);
        self::assertStringContainsString('Widerrufen', $html);
        self::assertStringNotContainsString('admin.tokens.', $html, 'no untranslated key');
    }

    private function render(string $locale): string
    {
        $translator = new Translator($locale);
        $translator->addLoader('yaml', new YamlFileLoader());
        foreach (['en', 'de'] as $catalogue) {
            $translator->addResource('yaml', self::ROOT."/translations/koh_mcp_oauth.{$catalogue}.yaml", $catalogue, 'koh_mcp_oauth');
        }

        $files = new FilesystemLoader();
        $files->addPath(self::ROOT.'/templates', 'KohSyliusMcpOAuth');
        $loader = new ChainLoader([
            new ArrayLoader(['@SyliusAdmin/shared/layout/base.html.twig' => '<title>{% block title %}Sylius{% endblock %}</title>{% block body %}{% endblock %}']),
            $files,
        ]);

        $twig = new Environment($loader, ['strict_variables' => true]);
        $twig->addExtension(new TranslationExtension($translator));
        $twig->addFunction(new TwigFunction('path', static fn (string $route, array $params = []): string => match ($route) {
            'mcp_oauth_admin_token_revoke' => '/admin/mcp/access-tokens/'.$params['id'].'/revoke',
            default => '/admin/',
        }));
        $twig->addFunction(new TwigFunction('csrf_token', static fn (string $id): string => 'csrf-for-'.$id));

        $token = new McpAccessToken(hash('sha256', 'x'), 7, 'Claude', ['mcp:read'], new \DateTimeImmutable('+1 hour'), 'mcpc_a');
        (new \ReflectionProperty(McpAccessToken::class, 'id'))->setValue($token, 5);
        $token->touch(ip: '198.51.100.4');

        return $twig->render(TokenAdminController::TEMPLATE, [
            'app' => new class {
                /** @return list<string> */
                public function flashes(string $type): array
                {
                    return [];
                }
            },
            'tokens' => [['token' => $token, 'owner' => 'admin@example.test', 'client' => 'Claude Desktop', 'status' => 'active']],
            'translation_domain' => 'koh_mcp_oauth',
        ]);
    }
}
