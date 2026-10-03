<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\Entity\McpRefreshToken;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The token endpoint with refresh tokens switched on: a code exchange returns
 * a pair, a refresh returns a new pair in the same family, and the token is
 * bound to the resource of the authorization.
 */
final class TokenRefreshTest extends TestCase
{
    private const VERIFIER = 'a-verifier-long-enough-to-be-realistic-0123456789';
    private const CLIENT_ID = 'mcpc_abc';
    private const REDIRECT_URI = 'https://client.example/cb';
    private const RESOURCE = 'https://shop.example/_mcp';
    private const REFRESH = 'tbmcpr_known';

    /** @var list<object> */
    private array $persisted = [];

    public function testTheCodeExchangeReturnsARefreshToken(): void
    {
        $body = $this->call($this->codeRequest());

        self::assertStringStartsWith('tbmcp_', $body['access_token']);
        self::assertStringStartsWith(RefreshTokenManager::PREFIX, $body['refresh_token']);

        $access = $this->persistedOf(McpAccessToken::class);
        $refresh = $this->persistedOf(McpRefreshToken::class);
        self::assertSame(self::RESOURCE, $access->getAudience(), 'bound to the resource of the code');
        self::assertSame($refresh->getFamily(), $access->getRefreshFamily(), 'one family');
        self::assertSame('203.0.113.9', $access->getCreatedIp());
    }

    public function testARefreshReturnsANewPairInTheSameFamily(): void
    {
        $body = $this->call($this->refreshRequest());

        self::assertStringStartsWith('tbmcp_', $body['access_token']);
        self::assertNotSame(self::REFRESH, $body['refresh_token']);
        self::assertSame('family-1', $this->persistedOf(McpAccessToken::class)->getRefreshFamily());
        self::assertSame('family-1', $this->persistedOf(McpRefreshToken::class)->getFamily());
        self::assertSame('mcp:read mcp:write', $body['scope']);
    }

    public function testARefreshMayNarrowTheScope(): void
    {
        self::assertSame('mcp:read', $this->call($this->refreshRequest(['scope' => 'mcp:read']))['scope']);
    }

    public function testARefreshMayNotWidenTheScope(): void
    {
        $body = $this->call($this->refreshRequest(['scope' => 'mcp']), Response::HTTP_BAD_REQUEST);

        self::assertSame('invalid_scope', $body['error']);
    }

    public function testAResourceOtherThanTheBoundOneIsInvalidTarget(): void
    {
        $body = $this->call($this->refreshRequest(['resource' => 'https://other.example/mcp']), Response::HTTP_BAD_REQUEST);

        self::assertSame('invalid_target', $body['error']);
    }

    public function testWithoutRefreshTokensTheGrantIsUnsupported(): void
    {
        $body = $this->call($this->refreshRequest(), Response::HTTP_BAD_REQUEST, refreshTtl: 0);

        self::assertSame('unsupported_grant_type', $body['error']);
        self::assertArrayNotHasKey('refresh_token', $this->call($this->codeRequest(), refreshTtl: 0));
    }

    /**
     * @param array<string, string> $overrides
     */
    private function refreshRequest(array $overrides = []): Request
    {
        return Request::create('https://shop.example/mcp/oauth/token', 'POST', array_merge([
            'grant_type' => 'refresh_token',
            'refresh_token' => self::REFRESH,
            'client_id' => self::CLIENT_ID,
        ], $overrides), server: ['REMOTE_ADDR' => '203.0.113.9']);
    }

    private function codeRequest(): Request
    {
        return Request::create('https://shop.example/mcp/oauth/token', 'POST', [
            'grant_type' => 'authorization_code',
            'code' => 'raw-code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::VERIFIER,
            'resource' => self::RESOURCE,
        ], server: ['REMOTE_ADDR' => '203.0.113.9']);
    }

    /** @return array<string, mixed> */
    private function call(Request $request, int $status = Response::HTTP_OK, int $refreshTtl = 86400): array
    {
        $this->persisted = [];
        $entityManager = $this->entityManager();
        $controller = new TokenController(3600, $refreshTtl, new RefreshTokenManager($entityManager));

        $response = $controller(
            $request,
            new OAuthServer($entityManager, null, new RedirectUriPolicy([self::REDIRECT_URI])),
            new AccessTokenManager($entityManager),
        );

        self::assertSame($status, $response->getStatusCode(), (string) $response->getContent());
        /** @var array<string, mixed> $body */
        $body = json_decode((string) $response->getContent(), true);

        return $body;
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return T
     */
    private function persistedOf(string $class): object
    {
        foreach ($this->persisted as $entity) {
            if ($entity instanceof $class) {
                return $entity;
            }
        }
        self::fail('Nothing of '.$class.' was persisted.');
    }

    private function entityManager(): EntityManagerInterface
    {
        $code = new McpAuthorizationCode(
            codeHash: hash('sha256', 'raw-code'),
            clientId: self::CLIENT_ID,
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            codeChallengeMethod: 'S256',
            expiresAt: new \DateTimeImmutable('+300 seconds'),
            resource: self::RESOURCE,
        );
        $refresh = new McpRefreshToken(hash('sha256', self::REFRESH), 'family-1', 7, self::CLIENT_ID, ['mcp:read', 'mcp:write'], self::RESOURCE, new \DateTimeImmutable('+1 day'));

        $repositories = [];
        foreach ([McpAuthorizationCode::class => $code, McpRefreshToken::class => $refresh, McpOAuthClient::class => new McpOAuthClient(self::CLIENT_ID, 'My Client', [self::REDIRECT_URI])] as $class => $entity) {
            $repository = $this->createStub(EntityRepository::class);
            $repository->method('findOneBy')->willReturnCallback(static function (array $criteria) use ($entity): ?object {
                $hash = $criteria['tokenHash'] ?? $criteria['codeHash'] ?? null;

                return null === $hash || ($entity instanceof McpRefreshToken ? $entity->getTokenHash() === $hash : true) ? $entity : null;
            });
            $repositories[$class] = $repository;
        }

        $query = $this->createStub(Query::class);
        $query->method('setParameter')->willReturnSelf();
        $query->method('execute')->willReturn(1);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturnCallback(fn (string $class): EntityRepository => $repositories[$class] ?? $this->createStub(EntityRepository::class));
        $entityManager->method('createQuery')->willReturn($query);
        $entityManager->method('persist')->willReturnCallback(function (object $entity): void {
            $this->persisted[] = $entity;
        });

        return $entityManager;
    }
}
