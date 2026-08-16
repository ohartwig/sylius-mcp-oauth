<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * This class mints and validates the bearer tokens that grant admin-level MCP
 * access. Three properties carry the security of the whole scheme: the raw
 * token is never persisted, an invalid token never resolves, and a revoked or
 * expired token stops working immediately rather than at the next cache flush.
 */
#[CoversClass(AccessTokenManager::class)]
final class AccessTokenManagerTest extends TestCase
{
    public function testTheRawTokenIsNeverPersistedOnlyItsHash(): void
    {
        // A database leak must not hand over usable tokens. The stored value is
        // the SHA-256 of the raw token and nothing else.
        $persisted = null;
        $manager = $this->manager(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $result = $manager->create(adminUserId: 7, name: 'laptop');

        self::assertInstanceOf(McpAccessToken::class, $persisted);
        self::assertNotSame($result['token'], $persisted->getTokenHash());
        self::assertSame(hash('sha256', $result['token']), $persisted->getTokenHash());
        self::assertStringNotContainsString($result['token'], $persisted->getTokenHash());
    }

    public function testAMintedTokenCarriesTheRecognisablePrefix(): void
    {
        // findValid() rejects anything without the prefix before touching the
        // database, so minting without it would produce a token that can never
        // authenticate.
        $result = $this->manager()->create(adminUserId: 7, name: 'laptop');

        self::assertStringStartsWith('tbmcp_', $result['token']);
    }

    public function testTwoTokensAreNeverTheSame(): void
    {
        $manager = $this->manager();

        $first = $manager->create(adminUserId: 7, name: 'one')['token'];
        $second = $manager->create(adminUserId: 7, name: 'two')['token'];

        self::assertNotSame($first, $second);
    }

    public function testTheTokenCarriesEnoughEntropyToResistGuessing(): void
    {
        // 32 random bytes, hex-encoded. A shorter token would be enumerable.
        $token = $this->manager()->create(adminUserId: 7, name: 'laptop')['token'];

        self::assertSame(64, \strlen(substr($token, \strlen('tbmcp_'))));
        self::assertMatchesRegularExpression('/^tbmcp_[0-9a-f]{64}$/', $token);
    }

    public function testTheTokenIsBoundToTheRequestedAdminAndScopes(): void
    {
        $persisted = null;
        $manager = $this->manager(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $manager->create(adminUserId: 42, name: 'ci', scopes: ['mcp', 'read']);

        self::assertInstanceOf(McpAccessToken::class, $persisted);
        self::assertSame(42, $persisted->getAdminUserId());
        self::assertSame(['mcp', 'read'], $persisted->getScopes());
    }

    public function testAnUnspecifiedScopeDefaultsToMcp(): void
    {
        $persisted = null;
        $manager = $this->manager(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $manager->create(adminUserId: 7, name: 'laptop');

        self::assertInstanceOf(McpAccessToken::class, $persisted);
        self::assertSame(['mcp'], $persisted->getScopes());
    }

    public function testCreatingATokenFlushesIt(): void
    {
        // A persisted-but-unflushed token does not exist as far as any other
        // request is concerned; the caller believes a token was minted.
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $entityManager->expects(self::once())->method('flush');

        (new AccessTokenManager($entityManager))->create(adminUserId: 7, name: 'laptop');
    }

    public function testLookupHashesThePresentedTokenRatherThanQueryingItRaw(): void
    {
        // Querying the raw value would never match the stored column, and would
        // also mean the raw token reached the query log.
        $raw = 'tbmcp_' . str_repeat('a', 64);
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())
            ->method('findOneBy')
            ->with(['tokenHash' => hash('sha256', $raw)])
            ->willReturn(null);

        self::assertNull($this->manager(repository: $repository)->findValid($raw));
    }

    public function testAnEmptyTokenIsRejectedWithoutQuerying(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('findOneBy');

        self::assertNull($this->manager(repository: $repository)->findValid(''));
    }

    public function testATokenWithoutThePrefixIsRejectedWithoutQuerying(): void
    {
        // Cheap rejection of obviously foreign credentials keeps unrelated
        // bearer tokens from reaching the database at all.
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('findOneBy');

        self::assertNull($this->manager(repository: $repository)->findValid('github_pat_something'));
    }

    public function testARevokedTokenNoLongerResolves(): void
    {
        // Revocation is the only way to stop a leaked token; if it still
        // resolved, revoking would be cosmetic.
        $token = $this->token();
        $token->revoke();

        self::assertNull($this->managerFinding($token)->findValid($this->rawToken()));
    }

    public function testAnExpiredTokenNoLongerResolves(): void
    {
        $token = $this->token(expiresAt: new \DateTimeImmutable('-1 hour'));

        self::assertNull($this->managerFinding($token)->findValid($this->rawToken()));
    }

    public function testAValidTokenResolvesAndRecordsItsUse(): void
    {
        $token = $this->token();
        self::assertNull($token->getLastUsedAt());

        $resolved = $this->managerFinding($token)->findValid($this->rawToken());

        self::assertSame($token, $resolved);
        // Last-used is what lets an operator spot a token still in use before
        // deleting it, and a leaked one being used from somewhere unexpected.
        self::assertNotNull($token->getLastUsedAt());
    }

    public function testResolvingAValidTokenFlushesTheRecordedUse(): void
    {
        // touch() only updates the in-memory entity; without the flush the
        // last-used timestamp never reaches the database.
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findOneBy')->willReturn($this->token());

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->expects(self::once())->method('flush');

        (new AccessTokenManager($entityManager))->findValid($this->rawToken());
    }

    public function testATokenWithoutAnExpiryStaysValid(): void
    {
        $token = $this->token(expiresAt: null);

        self::assertSame($token, $this->managerFinding($token)->findValid($this->rawToken()));
    }

    public function testRevokingByRawTokenRevokesTheStoredEntity(): void
    {
        $token = $this->token();

        $this->managerFinding($token)->revokeRaw($this->rawToken());

        self::assertTrue($token->isRevoked());
    }

    public function testRevokeFlushesTheRevocation(): void
    {
        // A revoked-but-unflushed token is still accepted by the next request;
        // revoke() would be cosmetic without this.
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $entityManager->expects(self::once())->method('flush');

        (new AccessTokenManager($entityManager))->revoke($this->token());
    }

    public function testRevokeIsCallableFromOutsideTheClass(): void
    {
        // The management screen and RFC 7009's revokeRaw() both call this from
        // outside AccessTokenManager; it has to stay part of the public API.
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $token = $this->token();

        (new AccessTokenManager($entityManager))->revoke($token);

        self::assertTrue($token->isRevoked());
    }

    public function testRevokingByRawTokenLooksUpByTheHashedTokenSpecifically(): void
    {
        $raw = $this->rawToken();
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())
            ->method('findOneBy')
            ->with(['tokenHash' => hash('sha256', $raw)])
            ->willReturn(null);

        $this->manager(repository: $repository)->revokeRaw($raw);
    }

    public function testRevokingAnUnknownRawTokenIsASilentNoOp(): void
    {
        // RFC 7009 has the endpoint report success either way, so that a caller
        // cannot probe which tokens exist by watching the response.
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findOneBy')->willReturn(null);

        $this->manager(repository: $repository)->revokeRaw($this->rawToken());

        $this->addToAssertionCount(1);
    }

    public function testRevokingAForeignTokenNeverReachesTheDatabase(): void
    {
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::never())->method('findOneBy');

        $this->manager(repository: $repository)->revokeRaw('github_pat_something');
    }

    public function testTokensForAnAdminAreListedNewestFirst(): void
    {
        // The management screen shows these; a stale order makes the token an
        // operator just minted hard to find and easy to mistake for another.
        $repository = $this->createMock(EntityRepository::class);
        $repository->expects(self::once())
            ->method('findBy')
            ->with(['adminUserId' => 7], ['createdAt' => 'DESC'])
            ->willReturn([]);

        self::assertSame([], $this->manager(repository: $repository)->findForAdminUser(7));
    }

    /**
     * All of the admin's tokens must come back, not just the newest.
     *
     * A prior version of this suite only ever asked the repository for an
     * empty result, so a mutation that truncated the return value to its first
     * element whenever there was more than one went unnoticed.
     */
    public function testAllOfTheAdminsTokensAreReturnedNotJustTheFirst(): void
    {
        $first = $this->token();
        $second = $this->token();
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findBy')->willReturn([$first, $second]);

        self::assertSame([$first, $second], $this->manager(repository: $repository)->findForAdminUser(7));
    }

    // --- helpers -------------------------------------------------------------

    private function rawToken(): string
    {
        return 'tbmcp_' . str_repeat('b', 64);
    }

    private function token(?\DateTimeImmutable $expiresAt = null): McpAccessToken
    {
        return new McpAccessToken(
            tokenHash: hash('sha256', $this->rawToken()),
            adminUserId: 7,
            name: 'laptop',
            scopes: ['mcp'],
            expiresAt: $expiresAt,
        );
    }

    private function managerFinding(McpAccessToken $token): AccessTokenManager
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findOneBy')->willReturn($token);

        return $this->manager(repository: $repository);
    }

    private function manager(
        ?EntityRepository $repository = null,
        ?\Closure $persistCallback = null,
    ): AccessTokenManager {
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')
            ->willReturn($repository ?? $this->createStub(EntityRepository::class));

        if ($persistCallback !== null) {
            $entityManager->method('persist')->willReturnCallback($persistCallback);
        }

        return new AccessTokenManager($entityManager);
    }
}
