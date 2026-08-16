<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use PHPUnit\Framework\TestCase;

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
     */
    public function testTheOnSiteErrorPageCarriesTheEscapedMessageAndAnHtmlContentType(): void
    {
        $response = self::error('Ungültiger client_id oder redirect_uri.');

        self::assertSame(
            '<!doctype html><meta charset="utf-8"><title>MCP-Autorisierung</title>'
            . '<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">'
            . '<h1>MCP-Autorisierung fehlgeschlagen</h1><p>Ungültiger client_id oder redirect_uri.</p></body>',
            $response->getContent(),
        );
        self::assertSame('text/html; charset=utf-8', $response->headers->get('Content-Type'));
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

    private static function error(string $message): \Symfony\Component\HttpFoundation\Response
    {
        /** @var \Symfony\Component\HttpFoundation\Response $response */
        $response = (new \ReflectionMethod(AuthorizeController::class, 'error'))
            ->invoke(new AuthorizeController(), $message);

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
