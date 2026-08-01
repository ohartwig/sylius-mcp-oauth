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

    /** @return list<string>|null */
    private static function resolve(string $scope): ?array
    {
        /** @var list<string>|null $scopes */
        $scopes = (new \ReflectionMethod(AuthorizeController::class, 'resolveScopes'))
            ->invoke(new AuthorizeController(), $scope);

        return $scopes;
    }
}
