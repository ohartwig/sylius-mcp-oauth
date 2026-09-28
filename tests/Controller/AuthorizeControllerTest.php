<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Scope parsing on the authorization endpoint.
 *
 * Only the parsing is exercised here: it is the part that decides what a request
 * is authorised for, and it does so before any of the controller's collaborators
 * are involved.
 */
final class AuthorizeControllerTest extends TestCase
{
    public function testAnAbsentScopeFallsBackToMcp(): void
    {
        self::assertSame(['mcp'], self::resolve(''));
    }

    public function testRepeatedSpacesDoNotProduceEmptyScopes(): void
    {
        self::assertSame(['mcp'], self::resolve('  mcp   '));
    }

    public function testAnUnsupportedScopeEndsTheRequest(): void
    {
        self::assertNull(self::resolve('mcp admin'));
    }

    /**
     * The exception to the line above, and the reason it is written down.
     *
     * A requested scope of exactly "0" is dropped instead of refused, so
     * "mcp 0" is authorised as if only "mcp" had been asked for, and "0" alone
     * falls through to the default. Every other unsupported scope ends the
     * request with invalid_scope.
     *
     * That inconsistency is pinned here, not endorsed. Silently narrowing what a
     * client asked for is the failure mode OAuth's error responses exist to
     * prevent, so refusing "0" is very probably right — but it is a deliberate
     * change to the authorization path, and it has not been decided. When it is,
     * these two assertions are what has to change, on purpose and in review,
     * rather than a shift nobody notices.
     */
    public function testAScopeOfZeroIsDroppedRatherThanRefused(): void
    {
        self::assertSame(['mcp'], self::resolve('mcp 0'));
        self::assertSame(['mcp'], self::resolve('0'));
    }

    /**
     * A dropped leading scope must not leave a gap in the returned list's keys.
     *
     * array_filter() preserves the original indices of whatever it keeps, so
     * without the array_values() re-index the list returned here would carry
     * key 1, not 0 — still equal by value, but not by identity, and any caller
     * that relies on it being a genuine `list<string>` (json_encode() included:
     * a non-sequential array is encoded as a JSON object, not an array) would
     * see the difference before this method's caller ever would.
     */
    public function testADroppedLeadingScopeDoesNotLeaveAGapInTheKeys(): void
    {
        self::assertSame(['mcp'], self::resolve('0 mcp'));
    }

    /**
     * trim() and the '' filter look redundant — explode(' ', …) already turns
     * repeated spaces into empty strings the filter drops — but trim() also
     * strips whitespace explode() does not split on, such as a leading tab.
     * Without it, "\tmcp" survives as one non-empty, unsupported "token".
     */
    public function testLeadingAndTrailingNonSpaceWhitespaceIsTrimmedBeforeSplitting(): void
    {
        self::assertSame(['mcp'], self::resolve("\tmcp\n"));
    }

    /**
     * The on-site error page, exercised directly: it is what an attacker-chosen
     * client_id or redirect_uri is shown instead of a redirect, so its exact
     * markup and headers are part of the open-redirect defence, not decoration.
     *
     * THR-AGENT-021: without a translator it speaks English, not German.
     */
    public function testTheOnSiteErrorPageIsEnglishByDefaultAndCarriesTheOAuthError(): void
    {
        $response = self::error(new AuthorizeController(), 'error.invalid_client', 'invalid_request');
        $html = (string) $response->getContent();

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('text/html; charset=utf-8', $response->headers->get('Content-Type'));
        self::assertStringContainsString('<html lang="en">', $html);
        self::assertStringContainsString('<title>MCP authorisation failed</title>', $html);
        self::assertStringContainsString(
            '<p role="alert">Unknown client_id, or a redirect_uri this client has not registered.</p>',
            $html,
        );
        self::assertStringContainsString('Error code: <code>invalid_request</code>', $html);
        self::assertStringNotContainsString('Ungültig', $html);
        self::assertStringNotContainsString('fehlgeschlagen', $html);
    }

    public function testTheOnSiteErrorPageIsTranslatedWhenATranslatorIsAvailable(): void
    {
        $translator = $this->createStub(TranslatorInterface::class);
        $translator->method('getLocale')->willReturn('de_DE');
        $translator->method('trans')->willReturnCallback(
            static fn (string $id, array $parameters = [], ?string $domain = null): string => match (true) {
                'koh_mcp_oauth' !== $domain => $id,
                'error.title' === $id => 'MCP-Autorisierung fehlgeschlagen',
                'error.not_signed_in' === $id => 'Kein Administrator <angemeldet>.',
                default => $id,
            },
        );

        $html = (string) self::error(new AuthorizeController($translator), 'error.not_signed_in', 'access_denied')->getContent();

        self::assertStringContainsString('<html lang="de-DE">', $html);
        self::assertStringContainsString('<title>MCP-Autorisierung fehlgeschlagen</title>', $html);
        // Translations are escaped like any other text.
        self::assertStringContainsString('Kein Administrator &lt;angemeldet&gt;.', $html);
        // A key missing from the catalogue falls back to English, never to the key.
        self::assertStringContainsString('Error code: <code>access_denied</code>', $html);
        self::assertStringNotContainsString('error.code', $html);
    }

    /**
     * appendQuery() drops empty values rather than emitting `key=` for them —
     * this is what keeps an unset `state` out of the redirect back to the
     * client, instead of it arriving as an empty query parameter.
     */
    public function testAppendQueryDropsEmptyValuesButKeepsNonEmptyOnes(): void
    {
        self::assertSame(
            'https://client.example/cb?code=abc123',
            self::appendQuery('https://client.example/cb', ['code' => 'abc123', 'state' => '']),
        );
    }

    /** @return list<string>|null */
    private static function resolve(string $scope): ?array
    {
        /** @var list<string>|null $scopes */
        $scopes = (new \ReflectionMethod(AuthorizeController::class, 'resolveScopes'))
            ->invoke(new AuthorizeController(), $scope);

        return $scopes;
    }

    private static function error(AuthorizeController $controller, string $key, string $oauthError): \Symfony\Component\HttpFoundation\Response
    {
        /** @var \Symfony\Component\HttpFoundation\Response $response */
        $response = (new \ReflectionMethod(AuthorizeController::class, 'error'))
            ->invoke($controller, $key, $oauthError);

        return $response;
    }

    /** @param array<string, string> $extra */
    private static function appendQuery(string $url, array $extra): string
    {
        /** @var string $result */
        $result = (new \ReflectionMethod(AuthorizeController::class, 'appendQuery'))
            ->invoke(new AuthorizeController(), $url, $extra);

        return $result;
    }
}
