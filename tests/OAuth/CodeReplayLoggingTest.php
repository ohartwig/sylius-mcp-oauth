<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\Query;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * A code that passes every check and is then found already spent means someone
 * redeemed it in between. Mandatory PKCE makes an intercepted code useless
 * without the verifier, so this is usually a client retrying — but it is the
 * only signal that would tell the two apart, and it used to be silent.
 */
final class CodeReplayLoggingTest extends TestCase
{
    private const VERIFIER = 'a-verifier-long-enough-to-be-realistic-0123456789';

    public function testLosingTheRaceIsLoggedAndRefused(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('warning')
            ->with(
                self::stringContains('redeemed twice'),
                self::callback(static function (array $ctx): bool {
                    // The full hash is the lookup key for a live code and must
                    // not reach the log; a prefix is enough to correlate. It
                    // has to be *the* prefix — the first 12 hex characters of
                    // the hash the lookup used — not merely 12 characters of
                    // something.
                    return $ctx['client_id'] === 'mcpc_abc'
                        && $ctx['code_hash_prefix'] === substr(hash('sha256', 'raw-code'), 0, 12);
                }),
            );

        $this->expectException(OAuthException::class);

        $this->server($logger, burned: 0)->consumeCode('raw-code', 'mcpc_abc', 'https://client.example/cb', self::VERIFIER);
    }

    public function testWinningTheRaceLogsNothing(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('warning');

        $result = $this->server($logger, burned: 1)
            ->consumeCode('raw-code', 'mcpc_abc', 'https://client.example/cb', self::VERIFIER);

        self::assertSame(7, $result['admin_user_id']);
    }

    public function testTheServerStillWorksWithoutALogger(): void
    {
        $this->expectException(OAuthException::class);

        $this->server(null, burned: 0)->consumeCode('raw-code', 'mcpc_abc', 'https://client.example/cb', self::VERIFIER);
    }

    private function server(?LoggerInterface $logger, int $burned): OAuthServer
    {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '=');

        $code = new McpAuthorizationCode(
            codeHash: hash('sha256', 'raw-code'),
            clientId: 'mcpc_abc',
            adminUserId: 7,
            redirectUri: 'https://client.example/cb',
            scopes: ['mcp'],
            codeChallenge: $challenge,
            codeChallengeMethod: 'S256',
            expiresAt: (new \DateTimeImmutable())->modify('+300 seconds'),
        );

        $codes = $this->createMock(EntityRepository::class);
        $codes->method('findOneBy')->willReturn($code);

        $clients = $this->createMock(EntityRepository::class);
        $clients->method('findOneBy')->willReturn(new McpOAuthClient('mcpc_abc', 'Client', ['https://client.example/cb']));

        $query = $this->createMock(Query::class);
        $query->method('setParameter')->willReturnSelf();
        $query->method('execute')->willReturn($burned);

        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturnCallback(
            static fn (string $class): EntityRepository => McpAuthorizationCode::class === $class ? $codes : $clients,
        );
        $em->method('createQuery')->willReturn($query);

        return new OAuthServer($em, $logger);
    }
}
