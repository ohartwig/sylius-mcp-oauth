<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Template;

use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\Twig\Extension\TranslationExtension;
use Symfony\Component\Translation\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;
use Symfony\Component\Yaml\Yaml;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

/**
 * THR-AGENT-021: the consent template ships with the bundle. Rendered here
 * with real Twig and the shipped catalogues, so a missing file, a broken
 * key or a dropped CSRF field fails the build rather than a fresh install.
 */
#[CoversNothing]
final class ConsentTemplateTest extends TestCase
{
    private const ROOT = __DIR__ . '/../..';

    public function testTheBundledTemplateRendersTheConsentFormInEnglish(): void
    {
        $html = $this->render('en');

        self::assertStringContainsString('<html lang="en">', $html);
        self::assertStringContainsString('<title>Authorise MCP access</title>', $html);
        self::assertStringContainsString('<form method="post" action="/admin/mcp/authorize">', $html);
        self::assertStringContainsString('name="_csrf_token" value="csrf-for-mcp_oauth_authorize"', $html);
        self::assertStringContainsString('name="decision" value="approve"', $html);
        self::assertStringContainsString('name="decision" value="deny"', $html);
        self::assertStringContainsString('Manage the shop through MCP', $html);
        self::assertStringContainsString('admin@example.test', $html);
    }

    public function testEveryRequestParameterIsCarriedIntoThePost(): void
    {
        $html = $this->render('en');

        foreach ($this->query() as $key => $value) {
            self::assertStringContainsString(
                \sprintf('<input type="hidden" name="%s" value="%s">', $key, htmlspecialchars($value, \ENT_QUOTES)),
                $html,
            );
        }
    }

    /** Consent phishing only works if the admin cannot see where the code goes. */
    public function testTheRedirectTargetIsShownToTheAdmin(): void
    {
        self::assertStringContainsString('<code>https://client.example/cb</code>', $this->render('en'));
    }

    public function testClientSuppliedTextIsEscaped(): void
    {
        $html = $this->render('en', clientName: '<script>alert(1)</script>');

        self::assertStringNotContainsString('<script>alert(1)</script>', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }

    public function testTheGermanCatalogueTranslatesTheScreen(): void
    {
        $html = $this->render('de');

        self::assertStringContainsString('<html lang="de">', $html);
        self::assertStringContainsString('MCP-Zugriff autorisieren', $html);
        self::assertStringNotContainsString('consent.', $html);
    }

    /** @return iterable<string, array{string}> */
    public static function locales(): iterable
    {
        yield 'en' => ['en'];
        yield 'de' => ['de'];
    }

    #[DataProvider('locales')]
    public function testNoTranslationKeyLeaksIntoTheRenderedPage(string $locale): void
    {
        self::assertDoesNotMatchRegularExpression('/\b(consent|error)\.[a-z_.]+/', $this->render($locale));
    }

    public function testTheCataloguesDefineTheSameKeys(): void
    {
        self::assertSame($this->keys('en'), $this->keys('de'));
    }

    /** The controller's hard-coded fallbacks must match the English catalogue. */
    public function testTheControllerFallbacksMatchTheEnglishCatalogue(): void
    {
        $fallbacks = (new \ReflectionClassConstant(AuthorizeController::class, 'FALLBACK_MESSAGES'))->getValue();
        self::assertIsArray($fallbacks);

        $english = $this->flatten(Yaml::parseFile(self::ROOT . '/translations/koh_mcp_oauth.en.yaml'));
        foreach ($fallbacks as $key => $message) {
            self::assertArrayHasKey($key, $english);
            self::assertSame($english[$key], $message, $key);
        }
    }

    private function render(string $locale, string $clientName = 'My Client'): string
    {
        $translator = new Translator($locale);
        $translator->addLoader('yaml', new YamlFileLoader());
        foreach (['en', 'de'] as $catalogue) {
            $translator->addResource('yaml', self::ROOT . "/translations/koh_mcp_oauth.{$catalogue}.yaml", $catalogue, 'koh_mcp_oauth');
        }
        $translator->setFallbackLocales(['en']);

        $loader = new FilesystemLoader();
        $loader->addPath(self::ROOT . '/templates', 'KohSyliusMcpOAuth');

        $twig = new Environment($loader, ['strict_variables' => false]);
        $twig->addExtension(new TranslationExtension($translator));
        $twig->addFunction(new TwigFunction('path', static fn (string $route): string => 'mcp_oauth_authorize' === $route ? '/admin/mcp/authorize' : '/unknown'));
        $twig->addFunction(new TwigFunction('csrf_token', static fn (string $id): string => 'csrf-for-' . $id));

        return $twig->render(AuthorizeController::TEMPLATE, [
            'app' => ['request' => ['locale' => $locale]],
            'client' => new McpOAuthClient('mcpc_abc', $clientName, ['https://client.example/cb']),
            'admin_label' => 'admin@example.test',
            'scopes' => ['mcp'],
            'csrf_id' => 'mcp_oauth_authorize',
            'query' => $this->query(),
            'redirect_uri' => 'https://client.example/cb',
            'translation_domain' => AuthorizeController::TRANSLATION_DOMAIN,
        ]);
    }

    /** @return array<string, string> */
    private function query(): array
    {
        return [
            'client_id' => 'mcpc_abc',
            'redirect_uri' => 'https://client.example/cb',
            'state' => 'st"ate',
            'scope' => 'mcp',
            'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            'code_challenge_method' => 'S256',
            'response_type' => 'code',
        ];
    }

    /** @return list<string> */
    private function keys(string $locale): array
    {
        $keys = array_keys($this->flatten(Yaml::parseFile(self::ROOT . "/translations/koh_mcp_oauth.{$locale}.yaml")));
        sort($keys);

        return $keys;
    }

    /**
     * @param mixed $tree
     *
     * @return array<string, string>
     */
    private function flatten(mixed $tree, string $prefix = ''): array
    {
        $flat = [];
        if (!\is_array($tree)) {
            return $flat;
        }
        foreach ($tree as $key => $value) {
            $path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
            if (\is_array($value)) {
                $flat += $this->flatten($value, $path);
            } else {
                $flat[$path] = (string) $value;
            }
        }

        return $flat;
    }
}
