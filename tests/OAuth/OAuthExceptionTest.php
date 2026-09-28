<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(OAuthException::class)]
final class OAuthExceptionTest extends TestCase
{
    public function testTheMessageIsTheDescriptionWhenOneIsGiven(): void
    {
        $exception = new OAuthException('invalid_grant', 'Authorization code is invalid.');

        self::assertSame('invalid_grant', $exception->error);
        self::assertSame('Authorization code is invalid.', $exception->getMessage());
    }

    /**
     * Every call site in this bundle passes a description, so this fallback is
     * otherwise untested — but it is still reachable (any future call site
     * could omit it), and the fallback is what keeps such a call from throwing
     * with an empty message.
     */
    public function testTheMessageFallsBackToTheErrorCodeWhenNoDescriptionIsGiven(): void
    {
        $exception = new OAuthException('invalid_client');

        self::assertSame('invalid_client', $exception->error);
        self::assertSame('invalid_client', $exception->getMessage());
    }
}
