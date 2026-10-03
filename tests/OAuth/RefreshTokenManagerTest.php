<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Koh\SyliusMcpOAuth\Entity\McpRefreshToken;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * A refresh token works once. The second use is the signal that someone else
 * holds it, and ends the whole authorization.
 */
final class RefreshTokenManagerTest extends TestCase
{
    private const RAW = 'tbmcpr_0123456789abcdef';

    /** @var list<string> */
    private array $queries = [];

    public function testAFreshTokenIsSpentAndReturned(): void
    {
        $token = $this->token();

        $spent = $this->manager($token, updated: 1)->rotate(self::RAW, 'mcpc_a');

        self::assertSame($token, $spent);
        self::assertNotNull($spent->getUsedAt());
        self::assertCount(1, $this->queries, 'only the spend, no revocation');
    }

    /**
     * The conditional UPDATE found the token already spent: one of the two
     * holders is not the client. Family revoked — refresh tokens and access
     * tokens — and the replay is logged.
     */
    public function testASpentTokenRevokesTheFamily(): void
    {
        $logger = new class extends AbstractLogger {
            /** @var list<string> */
            public array $messages = [];

            public function log($level, \Stringable|string $message, array $context = []): void
            {
                $this->messages[] = (string) $message;
            }
        };

        try {
            $this->manager($this->token(), updated: 0, logger: $logger)->rotate(self::RAW, 'mcpc_a');
            self::fail('A reused refresh token must not be accepted.');
        } catch (OAuthException $e) {
            self::assertSame('invalid_grant', $e->error);
        }

        self::assertCount(3, $this->queries);
        self::assertStringContainsString('r.family = :family', $this->queries[1]);
        self::assertStringContainsString('a.refreshFamily = :family', $this->queries[2]);
        self::assertStringContainsString('reused', $logger->messages[0] ?? '');
    }

    public function testATokenOfAnotherClientIsRefused(): void
    {
        $this->expectException(OAuthException::class);

        $this->manager($this->token(), updated: 1)->rotate(self::RAW, 'mcpc_other');
    }

    public function testExpiredRevokedAndUnknownTokensAreRefused(): void
    {
        $expired = new McpRefreshToken(hash('sha256', self::RAW), 'fam', 7, 'mcpc_a', ['mcp'], null, new \DateTimeImmutable('-1 second'));
        $revoked = $this->token();
        $revoked->revoke();

        foreach ([$expired, $revoked, null] as $token) {
            try {
                $this->manager($token, updated: 1)->rotate(self::RAW, 'mcpc_a');
                self::fail('Refused token accepted.');
            } catch (OAuthException $e) {
                self::assertSame('invalid_grant', $e->error);
            }
        }
    }

    private function token(): McpRefreshToken
    {
        return new McpRefreshToken(hash('sha256', self::RAW), 'family-1', 7, 'mcpc_a', ['mcp:write'], 'https://shop.example/_mcp', new \DateTimeImmutable('+1 day'));
    }

    private function manager(?McpRefreshToken $token, int $updated, ?AbstractLogger $logger = null): RefreshTokenManager
    {
        $this->queries = [];
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findOneBy')->willReturn($token);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->method('createQuery')->willReturnCallback(function (string $dql) use ($updated): Query {
            $this->queries[] = $dql;
            $query = $this->createStub(Query::class);
            $query->method('setParameter')->willReturnSelf();
            $query->method('execute')->willReturn(str_contains($dql, 'usedAt = :now') ? $updated : 1);

            return $query;
        });

        return new RefreshTokenManager($entityManager, $logger);
    }
}
