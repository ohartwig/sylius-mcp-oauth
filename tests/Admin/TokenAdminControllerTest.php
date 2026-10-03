<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Admin;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\Admin\TokenAdminController;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * The admin overview names who holds a token and through which client, and
 * revoking ends the token and everything a client could refresh it back with.
 */
final class TokenAdminControllerTest extends TestCase
{
    private McpAccessToken $token;

    /** @var array<string, mixed>|null */
    private ?array $rendered = null;

    /** @var list<string> */
    private array $queries = [];

    protected function setUp(): void
    {
        $this->token = new McpAccessToken(hash('sha256', 'x'), 7, 'Claude', ['mcp:read'], new \DateTimeImmutable('+1 hour'), 'mcpc_a', refreshFamily: 'fam-1', createdIp: '203.0.113.1');
        (new \ReflectionProperty(McpAccessToken::class, 'id'))->setValue($this->token, 5);
    }

    public function testTheOverviewNamesOwnerClientAndStatus(): void
    {
        $this->controller()->index();

        $row = $this->rendered['tokens'][0] ?? null;
        self::assertIsArray($row);
        self::assertSame('admin@example.test', $row['owner']);
        self::assertSame('Claude Desktop', $row['client']);
        self::assertSame('active', $row['status']);
    }

    public function testRevokingEndsTheTokenAndItsRefreshFamily(): void
    {
        $response = $this->controller()->revoke(5, $this->post('valid'));

        self::assertTrue($this->token->isRevoked());
        self::assertSame(302, $response->getStatusCode());
        self::assertCount(2, $this->queries, 'refresh tokens and access tokens of the family');
        self::assertStringContainsString('r.family = :family', $this->queries[0]);
        self::assertStringContainsString('a.refreshFamily = :family', $this->queries[1]);
    }

    public function testRevokingNeedsAValidCsrfToken(): void
    {
        $this->expectException(AccessDeniedException::class);

        try {
            $this->controller(csrfValid: false)->revoke(5, $this->post('forged'));
        } finally {
            self::assertFalse($this->token->isRevoked());
        }
    }

    public function testOnlyAdministratorsGetTheOverview(): void
    {
        $this->expectException(AccessDeniedException::class);

        $this->controller(granted: false)->index();
    }

    private function post(string $csrf): Request
    {
        $request = new Request(request: ['_token' => $csrf]);
        $request->setMethod('POST');

        return $request;
    }

    public function testTheOverviewRoleListsEveryonesTokensAndShowsStatus(): void
    {
        $this->token->revoke();

        $this->controller(currentAdminId: 8, overviewRole: 'ROLE_MCP_TOKEN_ADMIN', ownerExists: false)->index();

        $row = $this->rendered['tokens'][0] ?? null;
        self::assertIsArray($row);
        self::assertSame('revoked', $row['status']);
        self::assertSame('#7', $row['owner'], 'a deleted owner is shown by id');
    }

    public function testAnExpiredTokenIsShownAsExpired(): void
    {
        $expired = new McpAccessToken(hash('sha256', 'y'), 7, 'old', ['mcp'], new \DateTimeImmutable('-1 hour'));
        (new \ReflectionProperty(McpAccessToken::class, 'id'))->setValue($expired, 6);
        $this->token = $expired;

        $this->controller()->index();

        self::assertSame('expired', $this->rendered['tokens'][0]['status'] ?? null);
        self::assertIsArray($this->rendered['tokens'][0] ?? null);
        self::assertNull($this->rendered['tokens'][0]['client'], 'CLI tokens have no client');
    }

    public function testWithoutAnAdministratorThereIsNoOwnList(): void
    {
        $this->expectException(AccessDeniedException::class);

        $this->controller(currentAdminId: null)->index();
    }

    /** Without the overview role an administrator manages their own tokens only. */
    public function testAnotherAdministratorsTokenCannotBeRevoked(): void
    {
        $this->expectException(NotFoundHttpException::class);

        try {
            $this->controller(currentAdminId: 8)->revoke(5, $this->post('valid'));
        } finally {
            self::assertFalse($this->token->isRevoked());
        }
    }

    public function testTheOverviewRoleManagesEveryonesTokens(): void
    {
        $this->controller(currentAdminId: 8, overviewRole: 'ROLE_MCP_TOKEN_ADMIN')->revoke(5, $this->post('valid'));

        self::assertTrue($this->token->isRevoked());
    }

    private function controller(bool $csrfValid = true, bool $granted = true, ?int $currentAdminId = 7, ?string $overviewRole = null, bool $ownerExists = true): TokenAdminController
    {
        $tokens = $this->createStub(EntityRepository::class);
        $tokens->method('findBy')->willReturn([$this->token]);
        $tokens->method('find')->willReturn($this->token);
        $clients = $this->createStub(EntityRepository::class);
        $clients->method('findOneBy')->willReturn(new McpOAuthClient('mcpc_a', 'Claude Desktop', ['https://claude.ai/api/mcp/auth_callback']));

        $this->queries = [];
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturnCallback(static fn (string $class): EntityRepository => McpOAuthClient::class === $class ? $clients : $tokens);
        $entityManager->method('createQuery')->willReturnCallback(function (string $dql): Query {
            $this->queries[] = $dql;
            $query = $this->createStub(Query::class);
            $query->method('setParameter')->willReturnSelf();

            return $query;
        });

        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getEmail')->willReturn('admin@example.test');
        $admins = $this->createStub(ObjectRepository::class);
        $admins->method('find')->willReturn($ownerExists ? $admin : null);

        $controller = new TokenAdminController(new AccessTokenManager($entityManager), new OAuthServer($entityManager), $admins, new RefreshTokenManager($entityManager), $overviewRole);
        $controller->setContainer($this->container($csrfValid, $granted, $currentAdminId));

        return $controller;
    }

    private function container(bool $csrfValid, bool $granted, ?int $currentAdminId): ContainerInterface
    {
        $current = $this->createStub(AdminUserInterface::class);
        $current->method('getId')->willReturn($currentAdminId);
        $securityToken = $this->createStub(TokenInterface::class);
        $securityToken->method('getUser')->willReturn(null === $currentAdminId ? null : $current);
        $storage = $this->createStub(TokenStorageInterface::class);
        $storage->method('getToken')->willReturn($securityToken);

        $checker = $this->createStub(AuthorizationCheckerInterface::class);
        $checker->method('isGranted')->willReturn($granted);
        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);
        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturnCallback(function (string $name, array $context): string {
            $this->rendered = $context;

            return '<html></html>';
        });
        $router = $this->createStub(UrlGeneratorInterface::class);
        $router->method('generate')->willReturn('/admin/mcp/access-tokens');
        $requests = new RequestStack();
        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));
        $requests->push($request);

        $services = [
            'security.authorization_checker' => $checker,
            'security.csrf.token_manager' => $csrf,
            'twig' => $twig,
            'router' => $router,
            'request_stack' => $requests,
            'security.token_storage' => $storage,
        ];

        return new class($services) implements ContainerInterface {
            /** @param array<string, object> $services */
            public function __construct(private readonly array $services)
            {
            }

            public function get(string $id): object
            {
                return $this->services[$id] ?? throw new \RuntimeException('Service not stubbed: '.$id);
            }

            public function has(string $id): bool
            {
                return isset($this->services[$id]);
            }
        };
    }
}
