<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Security;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use Sylius\Component\Core\Model\ChannelInterface;
use Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

/**
 * This authenticator turns a bearer token into an admin identity on /_mcp, so
 * it is the boundary that decides whether a caller acts as a shop
 * administrator. Its 401 also carries the RFC 9728 pointer MCP clients follow
 * to find the authorization server — without it a client cannot discover how to
 * authenticate at all, so the header is part of the contract, not decoration.
 */
#[CoversClass(McpAccessTokenAuthenticator::class)]
final class McpAccessTokenAuthenticatorTest extends TestCase
{
    public function testItClaimsRequestsCarryingABearerToken(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer tbmcp_abc');

        self::assertTrue($this->authenticator()->supports($request));
    }

    #[DataProvider('unsupportedAuthorizationHeaders')]
    public function testItIgnoresRequestsItCannotAuthenticate(?string $header): void
    {
        // Claiming a Basic or an absent credential would break other
        // authenticators on the same firewall.
        $request = new Request();
        if ($header !== null) {
            $request->headers->set('Authorization', $header);
        }

        self::assertFalse($this->authenticator()->supports($request));
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function unsupportedAuthorizationHeaders(): iterable
    {
        yield 'no header' => [null];
        yield 'basic auth' => ['Basic dXNlcjpwYXNz'];
        yield 'empty' => [''];
        yield 'bearer without a space' => ['Bearertbmcp_abc'];
    }

    public function testAValidTokenAuthenticatesAsItsOwningAdmin(): void
    {
        $admin = $this->admin('ohartwig');
        $passport = $this->authenticator($this->knownToken(), $admin)
            ->authenticate($this->bearerRequest());

        self::assertSame('ohartwig', $passport->getUser()->getUserIdentifier());
        self::assertSame($admin, $passport->getUser());
    }

    public function testAnInvalidTokenIsRefused(): void
    {
        // findValid() returns null for unknown, revoked and expired tokens
        // alike; all three must end here rather than authenticating.
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('Invalid or expired MCP access token.');

        // No token resolves for this hash, which is what an unknown, revoked or
        // expired token looks like from here.
        $this->authenticator()->authenticate($this->bearerRequest());
    }

    public function testATokenWhoseOwnerWasDeletedIsRefused(): void
    {
        // Deleting an admin must revoke their access even though the token row
        // survives; otherwise the token authenticates as nobody.
        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('The MCP token owner no longer exists.');

        $this->authenticator($this->knownToken(), adminExists: false)
            ->authenticate($this->bearerRequest());
    }

    public function testTheTokenIsReadFromAnOrdinarySingleSpaceHeader(): void
    {
        // The common case. Slicing one character too far would eat the first
        // character of the token and every request would read as unauthorised.
        $raw = 'tbmcp_' . str_repeat('d', 64);
        $authenticator = $this->authenticator($this->knownToken(raw: $raw));

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $raw);

        $passport = $authenticator->authenticate($request);

        self::assertSame('admin@example.test', $passport->getUser()->getUserIdentifier());
    }

    public function testTheTokenIsReadWithoutItsBearerPrefixAndSurroundingSpace(): void
    {
        // A mis-sliced header would send "earer tbmcp_…" to the manager, which
        // fails the prefix check and reads as an invalid token.
        // The repository only resolves the hash of the exactly-trimmed value, so
        // this passes only if the header was sliced and trimmed correctly.
        $raw = 'tbmcp_' . str_repeat('c', 64);
        $authenticator = $this->authenticator($this->knownToken(raw: $raw));

        $request = new Request();
        $request->headers->set('Authorization', 'Bearer   ' . $raw . '   ');

        $passport = $authenticator->authenticate($request);

        self::assertSame('admin@example.test', $passport->getUser()->getUserIdentifier());
    }

    public function testAFailedAuthenticationAnswers401(): void
    {
        $response = $this->authenticator()->onAuthenticationFailure(
            new Request(),
            new CustomUserMessageAuthenticationException('Invalid or expired MCP access token.'),
        );

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testAFailedAuthenticationPointsAtTheProtectedResourceMetadata(): void
    {
        // RFC 9728. This header is how an MCP client discovers the authorization
        // server; without it the client has nowhere to go after a 401.
        $request = Request::create('https://shop.example/_mcp');

        $response = $this->authenticator()->onAuthenticationFailure(
            $request,
            new CustomUserMessageAuthenticationException('nope'),
        );

        self::assertSame(
            'Bearer resource_metadata="https://shop.example/.well-known/oauth-protected-resource"',
            $response->headers->get('WWW-Authenticate'),
        );
    }

    public function testTheEntryPointAlsoAnswers401WithTheDiscoveryPointer(): void
    {
        // An unauthenticated request never reaches authenticate(), so the entry
        // point must carry the same pointer or discovery breaks for new clients.
        $response = $this->authenticator()->start(Request::create('https://shop.example/_mcp'));

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringContainsString(
            'resource_metadata="https://shop.example/.well-known/oauth-protected-resource"',
            (string) $response->headers->get('WWW-Authenticate'),
        );
    }

    public function testTheDiscoveryPointerFollowsTheRequestHost(): void
    {
        // Multi-tenant installs answer on several hosts; a hardcoded host would
        // send every client to one tenant's metadata.
        $response = $this->authenticator()->start(Request::create('https://other.example/_mcp'));

        self::assertStringContainsString('https://other.example/', (string) $response->headers->get('WWW-Authenticate'));
    }

    public function testTheFailureBodyNamesTheErrorWithoutLeakingTheToken(): void
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer tbmcp_secret_value');

        $response = $this->authenticator()->onAuthenticationFailure(
            $request,
            new CustomUserMessageAuthenticationException('Invalid or expired MCP access token.'),
        );

        $body = (string) $response->getContent();

        self::assertStringContainsString('unauthorized', $body);
        self::assertStringNotContainsString('tbmcp_secret_value', $body);
    }

    public function testASuccessfulAuthenticationLetsTheRequestContinue(): void
    {
        // Returning a response here would answer the caller instead of running
        // the MCP controller they asked for.
        self::assertNull(
            $this->authenticator()->onAuthenticationSuccess(
                new Request(),
                $this->createStub(\Symfony\Component\Security\Core\Authentication\Token\TokenInterface::class),
                'mcp',
            ),
        );
    }

    /**
     * RFC 8707: a token bound to another resource is refused, however valid
     * it is otherwise.
     */
    public function testATokenForAnotherResourceIsRefused(): void
    {
        $token = new McpAccessToken(hash('sha256', self::RAW), 7, 'laptop', audience: 'https://other.example/_mcp');

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('different resource');

        $this->authenticator($this->knownToken($token), resource: $this->resource())->authenticate($this->bearerRequest());
    }

    public function testATokenForThisResourceIsAccepted(): void
    {
        $token = new McpAccessToken(hash('sha256', self::RAW), 7, 'laptop', audience: 'https://shop.example/_mcp');

        $passport = $this->authenticator($this->knownToken($token), resource: $this->resource())->authenticate($this->bearerRequest());

        self::assertSame('admin@example.test', $passport->getUser()->getUserIdentifier());
    }

    /** Tokens from before audience binding, and CLI tokens, carry none and keep working. */
    public function testATokenWithoutAudienceIsAccepted(): void
    {
        $passport = $this->authenticator($this->knownToken(), resource: $this->resource())->authenticate($this->bearerRequest());

        self::assertSame('admin@example.test', $passport->getUser()->getUserIdentifier());
    }

    /**
     * The contract with koh/sylius-mcp: the scopes and the token's identity
     * travel as security-token attributes under these exact names.
     */
    public function testTheTokenFactsBecomeSecurityTokenAttributes(): void
    {
        $token = new McpAccessToken(hash('sha256', self::RAW), 7, 'laptop', ['mcp:read'], clientId: 'mcpc_x', audience: null);
        $authenticator = $this->authenticator($this->knownToken($token));

        $securityToken = $authenticator->createToken($authenticator->authenticate($this->bearerRequest()), 'mcp');

        self::assertSame(['mcp:read'], $securityToken->getAttribute('koh_mcp.scopes'));
        self::assertSame('mcpc_x', $securityToken->getAttribute('koh_mcp.client_id'));
        self::assertTrue($securityToken->hasAttribute('koh_mcp.token_id'));
        self::assertTrue($securityToken->hasAttribute('koh_mcp.audience'));
    }

    public function testTheCallersAddressIsRecordedOnTheToken(): void
    {
        $token = $this->validToken();
        $request = $this->bearerRequest();
        $request->server->set('REMOTE_ADDR', '198.51.100.23');

        $this->authenticator($this->knownToken($token))->authenticate($request);

        self::assertSame('198.51.100.23', $token->getLastUsedIp());
        self::assertNotNull($token->getLastUsedAt());
    }

    // --- helpers -------------------------------------------------------------

    private function resource(): ResourceIndicator
    {
        $factory = $this->createStub(AgentContextFactoryInterface::class);
        $factory->method('create')->willReturn(new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US'));

        return new ResourceIndicator($factory, '/_mcp');
    }

    private const RAW = 'tbmcp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    private function bearerRequest(string $raw = self::RAW): Request
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer ' . $raw);

        return $request;
    }

    private function validToken(int $adminUserId = 7): McpAccessToken
    {
        return new McpAccessToken(
            tokenHash: hash('sha256', self::RAW),
            adminUserId: $adminUserId,
            name: 'laptop',
        );
    }

    private function admin(string $identifier = 'admin@example.test'): AdminUserInterface
    {
        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getUserIdentifier')->willReturn($identifier);

        return $admin;
    }

    /**
     * @return ObjectRepository<AdminUserInterface>
     */
    private function adminRepository(?AdminUserInterface $admin): ObjectRepository
    {
        $repository = $this->createStub(ObjectRepository::class);
        $repository->method('find')->willReturn($admin);

        return $repository;
    }

    /**
     * AccessTokenManager is final, so it is built for real over a stubbed entity
     * manager. The repository resolves a token only for the exact hash it is
     * keyed on, which means the manager's own prefix and hashing behaviour is
     * exercised rather than mocked away.
     *
     * @param array<string, McpAccessToken> $tokensByHash
     */
    private function manager(array $tokensByHash): AccessTokenManager
    {
        $repository = $this->createStub(EntityRepository::class);
        $repository->method('findOneBy')->willReturnCallback(
            static fn (array $criteria): ?McpAccessToken => $tokensByHash[$criteria['tokenHash']] ?? null,
        );

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);

        return new AccessTokenManager($entityManager);
    }

    /**
     * @param array<string, McpAccessToken>|null $tokensByHash null means no token resolves at all
     */
    private function authenticator(
        ?array $tokensByHash = null,
        ?AdminUserInterface $admin = null,
        bool $adminExists = true,
        ?ResourceIndicator $resource = null,
    ): McpAccessTokenAuthenticator {
        return new McpAccessTokenAuthenticator(
            $this->manager($tokensByHash ?? []),
            $this->adminRepository($adminExists ? ($admin ?? $this->admin()) : null),
            $resource,
        );
    }

    /**
     * @return array<string, McpAccessToken>
     */
    private function knownToken(?McpAccessToken $token = null, string $raw = self::RAW): array
    {
        return [hash('sha256', $raw) => $token ?? $this->validToken()];
    }
}
