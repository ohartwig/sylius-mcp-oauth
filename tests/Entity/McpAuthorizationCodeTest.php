<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Entity;

use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * isUsable() is the single gate that decides whether a code can still be
 * redeemed. It has to fail closed on both halves of its condition
 * independently — a used-but-unexpired code and an unused-but-expired code
 * must both be refused — and the boundary has to be strict: a code expiring
 * at exactly `$now` must already be unusable, not usable for one more instant.
 */
#[CoversClass(McpAuthorizationCode::class)]
final class McpAuthorizationCodeTest extends TestCase
{
    public function testAFreshUnusedCodeIsUsable(): void
    {
        self::assertTrue($this->code()->isUsable(new \DateTimeImmutable('2026-01-01 12:00:00')));
    }

    public function testAUsedCodeIsNotUsableEvenThoughItHasNotExpired(): void
    {
        $code = $this->code();
        $code->markUsed();

        self::assertFalse($code->isUsable(new \DateTimeImmutable('2026-01-01 12:00:00')));
    }

    public function testAnUnusedButExpiredCodeIsNotUsable(): void
    {
        self::assertFalse($this->code()->isUsable(new \DateTimeImmutable('2026-01-01 13:00:01')));
    }

    /**
     * The comparison is strict: expiring at exactly `$now` must already read
     * as expired, not as "expires this very instant, so still good".
     */
    public function testACodeExpiringAtExactlyNowIsNotUsable(): void
    {
        $expiresAt = new \DateTimeImmutable('2026-01-01 13:00:00');

        self::assertFalse($this->code(expiresAt: $expiresAt)->isUsable($expiresAt));
    }

    public function testACodeIsUsableOneSecondBeforeItExpires(): void
    {
        $expiresAt = new \DateTimeImmutable('2026-01-01 13:00:00');

        self::assertTrue($this->code(expiresAt: $expiresAt)->isUsable($expiresAt->modify('-1 second')));
    }

    /** Without an explicit $now, the check must fall back to the real clock. */
    public function testWithNoExplicitNowTheRealClockIsUsed(): void
    {
        $code = $this->code(expiresAt: new \DateTimeImmutable('+1 hour'));

        self::assertTrue($code->isUsable());

        $expired = $this->code(expiresAt: new \DateTimeImmutable('-1 hour'));

        self::assertFalse($expired->isUsable());
    }

    public function testMarkUsedMakesTheCodeUnusable(): void
    {
        $code = $this->code();
        self::assertTrue($code->isUsable(new \DateTimeImmutable('2026-01-01 12:00:00')));

        $code->markUsed();

        self::assertFalse($code->isUsable(new \DateTimeImmutable('2026-01-01 12:00:00')));
    }

    private function code(?\DateTimeImmutable $expiresAt = null): McpAuthorizationCode
    {
        return new McpAuthorizationCode(
            codeHash: hash('sha256', 'raw-code'),
            clientId: 'mcpc_abc',
            adminUserId: 7,
            redirectUri: 'https://client.example/cb',
            scopes: ['mcp'],
            codeChallenge: 'challenge',
            codeChallengeMethod: 'S256',
            expiresAt: $expiresAt ?? new \DateTimeImmutable('2026-01-01 13:00:00'),
        );
    }
}
