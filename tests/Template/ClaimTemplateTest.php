<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Template;

use Koh\SyliusMcpOAuth\Controller\AgentClaimController;
use Koh\SyliusMcpOAuth\Entity\McpAgentRegistration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Symfony\Component\Translation\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

/**
 * The claim page ships with the bundle; rendered with real Twig and the
 * shipped catalogues so a broken key or a dropped form field fails the build.
 */
#[CoversNothing]
final class ClaimTemplateTest extends TestCase
{
    private const ROOT = __DIR__.'/../..';

    public function testTheFormCarriesEverythingTheControllerReads(): void
    {
        $html = $this->render('en', 'form');

        self::assertStringContainsString('<form method="post" action="/admin/mcp/claim">', $html);
        self::assertStringContainsString('name="_csrf_token" value="csrf-for-mcp_agent_claim"', $html);
        self::assertStringContainsString('name="claim_attempt_token" value="tok&quot;en"', $html);
        self::assertStringContainsString('name="user_code"', $html);
        self::assertStringContainsString('<code>reg_abc</code> (anonymous)', $html);
        self::assertStringContainsString('198.51.100.7', $html);
        self::assertStringContainsString('Read the shop through MCP', $html);
        self::assertStringNotContainsString('role="alert"', $html);
    }

    public function testAWrongCodeIsAnnouncedWithTheAttemptsLeft(): void
    {
        $html = $this->render('de', 'wrong_code');

        self::assertStringContainsString('aria-invalid="true"', $html);
        self::assertStringContainsString('Verbleibende Versuche: 3.', $html);
    }

    /** @return iterable<string, array{string, string}> */
    public static function results(): iterable
    {
        foreach (['en', 'de'] as $locale) {
            foreach (['claimed', 'invalid', 'invalid_csrf', 'expired', 'locked', 'wrong_account'] as $state) {
                yield $locale.' '.$state => [$locale, $state];
            }
        }
    }

    #[DataProvider('results')]
    public function testEveryResultHasItsOwnTranslatedMessage(string $locale, string $state): void
    {
        $html = $this->render($locale, $state);

        self::assertDoesNotMatchRegularExpression('/\b(claim|consent)\.[a-z_.]+/', $html);
        self::assertStringNotContainsString('<form', $html);
        self::assertStringContainsString('claimed' === $state ? 'role="status"' : 'role="alert"', $html);
    }

    private function render(string $locale, string $state): string
    {
        $translator = new Translator($locale);
        $translator->addLoader('yaml', new YamlFileLoader());
        foreach (['en', 'de'] as $catalogue) {
            $translator->addResource('yaml', self::ROOT."/translations/koh_mcp_oauth.{$catalogue}.yaml", $catalogue, 'koh_mcp_oauth');
        }

        $loader = new FilesystemLoader();
        $loader->addPath(self::ROOT.'/templates', 'KohSyliusMcpOAuth');
        $twig = new Environment($loader, ['strict_variables' => true]);
        $twig->addExtension(new TranslationExtension($translator));
        $twig->addFunction(new TwigFunction('path', static fn (string $route): string => 'mcp_oauth_agent_claim' === $route ? '/admin/mcp/claim' : '/unknown'));
        $twig->addFunction(new TwigFunction('csrf_token', static fn (string $id): string => 'csrf-for-'.$id));

        $registration = new McpAgentRegistration('reg_abc', 'anonymous', 'h', new \DateTimeImmutable('+1 hour'), new \DateTimeImmutable('2026-11-05 12:00:00'), null, '198.51.100.7');
        $parameters = [
            'app' => ['request' => ['locale' => $locale]],
            'state' => $state,
            'scopes' => ['mcp:read'],
            'translation_domain' => 'koh_mcp_oauth',
        ];
        if (\in_array($state, ['form', 'wrong_code'], true)) {
            $parameters += [
                'registration' => $registration,
                'admin_label' => 'admin@example.test',
                'claim_attempt_token' => 'tok"en',
                'attempts_left' => 3,
                'csrf_id' => 'mcp_agent_claim',
            ];
        }

        return $twig->render(AgentClaimController::TEMPLATE, $parameters);
    }
}
