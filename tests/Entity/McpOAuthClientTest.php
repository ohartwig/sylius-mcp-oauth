<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Entity;

use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(McpOAuthClient::class)]
final class McpOAuthClientTest extends TestCase
{
    /**
     * Every client registered through RFC 7591 is a public client using the
     * authorization_code grant; this is the default OAuthServer::registerClient()
     * relies on rather than naming it explicitly.
     */
    public function testAClientWithNoExplicitGrantTypesDefaultsToAuthorizationCode(): void
    {
        $client = new McpOAuthClient('mcpc_abc', 'My Client', ['https://client.example/cb']);

        self::assertSame(['authorization_code'], $client->getGrantTypes());
    }
}
