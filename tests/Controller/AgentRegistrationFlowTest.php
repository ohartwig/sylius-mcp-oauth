<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
use Koh\SyliusMcpOAuth\Agent\IdentityAssertionSigner;
use Koh\SyliusMcpOAuth\Controller\AgentClaimController;
use Koh\SyliusMcpOAuth\Controller\AgentIdentityController;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use Koh\SyliusMcpOAuth\Tests\Agent\RegistrationStore;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Sylius\Component\Core\Model\AdminUserInterface;
use Sylius\Component\Core\Model\ChannelInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * The auth.md agent registration end to end, through the HTTP layer: register,
 * start the claim, an administrator confirms in the admin, the agent polls and
 * then refreshes with its assertion. And the other side: without the
 * administrator nothing yields an MCP token.
 */
#[CoversClass(AgentIdentityController::class)]
#[CoversClass(AgentClaimController::class)]
#[CoversClass(TokenController::class)]
final class AgentRegistrationFlowTest extends TestCase
{
    private RegistrationStore $store;

    /** @var list<McpAccessToken> */
    private array $tokens = [];

    protected function setUp(): void
    {
        $this->store = new RegistrationStore();
    }

    public function testTheWholeCeremonyEndsWithATokenForTheClaimingAdministrator(): void
    {
        $registration = $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])));
        self::assertSame('anonymous', $registration['registration_type']);
        self::assertSame('https://shop.example/mcp/oauth/agent/identity/claim', $registration['claim_url']);

        // Before the claim: pending, and the pre-claim assertion buys nothing.
        $pending = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']]);
        self::assertSame(400, $pending->getStatusCode());
        self::assertSame('authorization_pending', $this->json($pending)['error']);
        $preClaim = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_JWT_BEARER, 'assertion' => $registration['identity_assertion']]);
        self::assertSame('invalid_scope', $this->json($preClaim)['error']);
        self::assertSame([], $this->tokens);

        $claim = $this->json($this->identity()->claim($this->post(['claim_token' => $registration['claim_token'], 'email' => 'admin@shop.example'])));
        self::assertSame('initiated', $claim['status']);
        $verification = $claim['claim_attempt']['verification_uri'];
        self::assertStringStartsWith('https://shop.example/admin/mcp/claim?claim_attempt_token=', $verification);

        // The administrator opens the link and types the code.
        $page = $this->claimPage(Request::create($verification));
        self::assertSame(200, $page['response']->getStatusCode());
        self::assertSame('form', $page['context']['state']);
        self::assertSame(['mcp:read'], $page['context']['scopes']);
        self::assertSame('admin@shop.example', $page['context']['admin_label']);
        self::assertSame(5, $page['context']['attempts_left']);
        self::assertSame($this->store->rows[0], $page['context']['registration']);
        self::assertSame("frame-ancestors 'none'", $page['response']->headers->get('Content-Security-Policy'));
        self::assertSame('no-referrer', $page['response']->headers->get('Referrer-Policy'));
        self::assertSame('DENY', $page['response']->headers->get('X-Frame-Options'));
        self::assertTrue($page['response']->headers->hasCacheControlDirective('no-store'));

        $token = $this->attemptToken($verification);
        $confirmed = $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $claim['claim_attempt']['user_code'], '_csrf_token' => 't']));
        self::assertSame('claimed', $confirmed['context']['state']);

        $issued = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']]);
        self::assertSame(200, $issued->getStatusCode(), (string) $issued->getContent());
        $body = $this->json($issued);
        self::assertSame(['access_token', 'token_type', 'expires_in', 'scope', 'identity_assertion', 'assertion_expires'], array_keys($body));
        self::assertSame('mcp:read', $body['scope']);
        self::assertCount(1, $this->tokens);
        self::assertSame(7, $this->tokens[0]->getAdminUserId());
        self::assertSame($registration['registration_id'], $this->tokens[0]->getClientId());
        self::assertSame('https://shop.example/_mcp', $this->tokens[0]->getAudience());
        self::assertTrue($issued->headers->hasCacheControlDirective('no-store'));

        // The claim token is spent; the assertion mints the next token.
        self::assertSame('invalid_grant', $this->json($this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']]))['error']);
        $refreshed = $this->json($this->tokenEndpoint(['grant_type' => TokenController::GRANT_JWT_BEARER, 'assertion' => $body['identity_assertion'], 'resource' => 'https://shop.example/_mcp']));
        self::assertArrayNotHasKey('identity_assertion', $refreshed);
        self::assertSame('mcp:read', $refreshed['scope']);
        self::assertCount(2, $this->tokens);
    }

    public function testAnAssertionForAnotherResourceIsRefused(): void
    {
        $assertion = $this->claimedAssertion();

        $response = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_JWT_BEARER, 'assertion' => $assertion, 'resource' => 'https://elsewhere.example/_mcp']);

        self::assertSame('invalid_target', $this->json($response)['error']);
    }

    /** A disabled or deleted administrator ends what their claim granted. */
    public function testTheClaimingAdministratorMustStillBeAllowedIn(): void
    {
        $assertion = $this->claimedAssertion();

        $response = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_JWT_BEARER, 'assertion' => $assertion], adminExists: false);

        self::assertSame('invalid_grant', $this->json($response)['error']);
    }

    public function testWithAgentRegistrationOffTheGrantsAreUnknown(): void
    {
        $response = $this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => 'clm_x'], enabled: false);

        self::assertSame('unsupported_grant_type', $this->json($response)['error']);
        self::assertSame('Supported grant types: authorization_code.', $this->json($response)['error_description']);
        self::assertStringContainsString(
            TokenController::GRANT_AGENT_CLAIM,
            $this->json($this->tokenEndpoint(['grant_type' => 'password']))['error_description'],
        );
    }

    /** The issuer comes from the channel, not from whatever host the request reached. */
    public function testTheAssertionIssuerIsTheChannelUrl(): void
    {
        $registration = $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])));
        [$token, $code] = $this->openAttempt(null, $registration['claim_token']);
        $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $code, '_csrf_token' => 't']));

        $body = $this->json($this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']], host: 'http://10.0.0.5:8080'));

        self::assertSame('https://shop.example', (new IdentityAssertionSigner('s'))->verify($body['identity_assertion'])['iss'] ?? null);
    }

    public function testWithoutAChannelTheIssuerIsTheRequestHost(): void
    {
        $registration = $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])));
        [$token, $code] = $this->openAttempt(null, $registration['claim_token']);
        $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $code, '_csrf_token' => 't']));

        $body = $this->json($this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']], host: 'http://10.0.0.5:8080', withContext: false));

        self::assertSame('http://10.0.0.5:8080', (new IdentityAssertionSigner('s'))->verify($body['identity_assertion'])['iss'] ?? null);
        self::assertNull($this->tokens[0]->getAudience());
    }

    public function testTheAgentGrantsAreOnUnlessSwitchedOff(): void
    {
        $controller = new TokenController(refreshTokenTtl: 60, refreshTokens: new \Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager($this->createStub(EntityManagerInterface::class)), agentRegistrations: $this->manager());
        $entityManager = $this->createStub(EntityManagerInterface::class);

        $response = $controller(Request::create('/mcp/oauth/token', 'POST', ['grant_type' => 'password']), new OAuthServer($entityManager), new AccessTokenManager($entityManager));

        self::assertSame(
            'Supported grant types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer, urn:workos:agent-auth:grant-type:claim.',
            $this->json($response)['error_description'],
        );
    }

    public function testTheIdentityEndpointAnswersInTheAuthMdErrorShape(): void
    {
        $response = $this->identity()->identity($this->post(['type' => 'identity_assertion']));

        self::assertSame(400, $response->getStatusCode());
        self::assertSame(['error' => 'issuer_not_enabled', 'error_description' => 'This service trusts no identity provider; register as anonymous or service_auth.'], $this->json($response));
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    public function testServiceAuthPassesTheLoginHint(): void
    {
        $body = $this->json($this->identity()->identity($this->post(['type' => 'service_auth', 'login_hint' => 'admin@shop.example'])));

        self::assertSame('service_auth', $body['registration_type']);
        self::assertSame('admin@shop.example', $this->store->rows[0]->getClaimEmail());
        self::assertSame('203.0.113.9', $this->store->rows[0]->getCreatedIp());
    }

    /** @return iterable<string, array{string}> */
    public static function badBodies(): iterable
    {
        yield 'not JSON' => ['type=anonymous'];
        yield 'a list' => ['["anonymous"]'];
        yield 'empty' => [''];
        yield 'a string' => ['"anonymous"'];
        yield 'type not a string' => ['{"type": 1}'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('badBodies')]
    public function testAMalformedBodyIsAnInvalidRequest(string $content): void
    {
        $response = $this->identity()->identity(Request::create('/mcp/oauth/agent/identity', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9'], content: $content));

        self::assertSame(400, $response->getStatusCode());
        self::assertSame('invalid_request', $this->json($response)['error']);
        self::assertSame([], $this->store->rows);
    }

    public function testTheClaimEndpointIgnoresNonStringFields(): void
    {
        $response = $this->identity()->claim($this->post(['claim_token' => 5, 'email' => ['x']]));

        self::assertSame('invalid_claim_token', $this->json($response)['error']);
    }

    public function testTheClaimEndpointPassesTheEmail(): void
    {
        $registration = $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])));

        $response = $this->identity()->claim($this->post(['claim_token' => $registration['claim_token'], 'email' => 'x@shop.example']));

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('x@shop.example', $this->store->rows[0]->getClaimEmail());
    }

    /** Registrations and claim attempts share one per-address budget, answered with `rate_limited`. */
    public function testRegistrationIsRateLimitedPerAddress(): void
    {
        $limiter = new EndpointRateLimiter(['identity' => new RateLimiterFactory(['id' => 'i', 'policy' => 'fixed_window', 'limit' => 1, 'interval' => '1 hour'], new InMemoryStorage())]);
        $controller = $this->identity($limiter);

        self::assertSame(200, $controller->identity($this->post(['type' => 'anonymous']))->getStatusCode());
        $limited = $controller->claim($this->post(['claim_token' => 'x']));

        self::assertSame(429, $limited->getStatusCode());
        self::assertSame('rate_limited', $this->json($limited)['error']);
        self::assertCount(1, $this->store->rows);
    }

    public function testTheEndpointsAreGoneWhenAgentRegistrationIsOff(): void
    {
        $controller = new AgentIdentityController($this->manager(), $this->contextFactory(), enabled: false);

        $this->expectException(NotFoundHttpException::class);
        $controller->identity($this->post(['type' => 'anonymous']));
    }

    public function testTheClaimPageIsGoneWhenAgentRegistrationIsOff(): void
    {
        $controller = new AgentClaimController($this->manager(), false);
        $controller->setContainer($this->container());

        $this->expectException(NotFoundHttpException::class);
        $controller(Request::create('/admin/mcp/claim'));
    }

    public function testAnUnknownLinkShowsAnErrorPage(): void
    {
        $page = $this->claimPage(Request::create('/admin/mcp/claim?claim_attempt_token=nope'));

        self::assertSame(404, $page['response']->getStatusCode());
        self::assertSame('invalid', $page['context']['state']);
        self::assertSame(AgentClaimController::TEMPLATE, $page['template']);
    }

    public function testAWrongCodeShowsTheFormAgainWithFewerAttempts(): void
    {
        [$token, $code] = $this->openAttempt();

        $page = $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => '000000' === $code ? '111111' : '000000', '_csrf_token' => 't']));

        self::assertSame(400, $page['response']->getStatusCode());
        self::assertSame('wrong_code', $page['context']['state']);
        self::assertSame(4, $page['context']['attempts_left']);
        self::assertSame($token, $page['context']['claim_attempt_token']);
        self::assertSame('mcp_agent_claim', $page['context']['csrf_id']);
        self::assertSame('koh_mcp_oauth', $page['context']['translation_domain']);
    }

    public function testAnInvalidCsrfTokenClaimsNothing(): void
    {
        [$token, $code] = $this->openAttempt();

        $page = $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $code]), csrfValid: false);

        self::assertSame(400, $page['response']->getStatusCode());
        self::assertSame('invalid_csrf', $page['context']['state']);
        self::assertFalse($this->store->rows[0]->isClaimed());
    }

    public function testTheWrongAccountIsToldSo(): void
    {
        [$token, $code] = $this->openAttempt('owner@shop.example');

        $page = $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $code, '_csrf_token' => 't']));

        self::assertSame(400, $page['response']->getStatusCode());
        self::assertSame('wrong_account', $page['context']['state']);
    }

    public function testWithoutASignedInAdministratorTheClaimPageRefuses(): void
    {
        $controller = new AgentClaimController($this->manager());
        $controller->setContainer($this->container(null));

        $this->expectException(AccessDeniedException::class);
        $controller(Request::create('/admin/mcp/claim'));
    }

    private function claimedAssertion(): string
    {
        $registration = $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])));
        [$token, $code] = $this->openAttempt(null, $registration['claim_token']);
        $this->claimPage(Request::create('/admin/mcp/claim', 'POST', ['claim_attempt_token' => $token, 'user_code' => $code, '_csrf_token' => 't']));

        return $this->json($this->tokenEndpoint(['grant_type' => TokenController::GRANT_AGENT_CLAIM, 'claim_token' => $registration['claim_token']]))['identity_assertion'];
    }

    /** @return array{string, string} attempt token and user code */
    private function openAttempt(?string $email = null, ?string $claimToken = null): array
    {
        $claimToken ??= $this->json($this->identity()->identity($this->post(['type' => 'anonymous'])))['claim_token'];
        $claim = $this->json($this->identity()->claim($this->post(['claim_token' => $claimToken] + (null !== $email ? ['email' => $email] : []))));

        return [$this->attemptToken($claim['claim_attempt']['verification_uri']), $claim['claim_attempt']['user_code']];
    }

    private function manager(): AgentRegistrationManager
    {
        return new AgentRegistrationManager($this->store->entityManager($this), new IdentityAssertionSigner('s'), ['mcp:read']);
    }

    private function identity(?EndpointRateLimiter $limiter = null): AgentIdentityController
    {
        return new AgentIdentityController($this->manager(), $this->contextFactory(), $limiter ?? new EndpointRateLimiter());
    }

    /**
     * @param array<string, string> $form
     */
    private function tokenEndpoint(array $form, bool $enabled = true, bool $adminExists = true, string $host = 'https://shop.example', bool $withContext = true): JsonResponse
    {
        $tokens = $this->createStub(EntityRepository::class);
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($tokens);
        $entityManager->method('persist')->willReturnCallback(function (object $token): void {
            \assert($token instanceof McpAccessToken);
            $this->tokens[] = $token;
        });

        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('isEnabled')->willReturn(true);
        $admins = $this->createStub(ObjectRepository::class);
        $admins->method('find')->willReturn($adminExists ? $admin : null);

        $controller = new TokenController(
            resource: $withContext ? new ResourceIndicator($this->contextFactory()) : null,
            adminUsers: $admins,
            agentRegistrations: $this->manager(),
            contextFactory: $withContext ? $this->contextFactory() : null,
            agentRegistrationEnabled: $enabled,
        );

        $response = $controller(Request::create($host.'/mcp/oauth/token', 'POST', $form), new OAuthServer($entityManager), new AccessTokenManager($entityManager));
        self::assertInstanceOf(JsonResponse::class, $response);

        return $response;
    }

    /** @return array{response: Response, context: array<string, mixed>, template: string|null} */
    private function claimPage(Request $request, bool $csrfValid = true): array
    {
        $context = [];
        $template = null;
        $controller = new AgentClaimController($this->manager());
        $controller->setContainer($this->container($this->admin(), $csrfValid, $context, $template));
        $response = $controller($request);

        return ['response' => $response, 'context' => $context, 'template' => $template];
    }

    private function admin(): AdminUserInterface
    {
        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getId')->willReturn(7);
        $admin->method('getEmail')->willReturn('admin@shop.example');
        $admin->method('getUserIdentifier')->willReturn('admin-login');

        return $admin;
    }

    /** @param array<string, mixed> $context */
    private function container(?AdminUserInterface $admin = null, bool $csrfValid = true, array &$context = [], ?string &$template = null): ContainerInterface
    {
        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        if (null !== $admin) {
            $securityToken = $this->createStub(TokenInterface::class);
            $securityToken->method('getUser')->willReturn($admin);
            $tokenStorage->method('getToken')->willReturn($securityToken);
        }

        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturnCallback(function (string $name, array $parameters) use (&$context, &$template): string {
            $context = $parameters;
            $template = $name;

            return '<html>claim</html>';
        });

        $services = ['security.token_storage' => $tokenStorage, 'security.csrf.token_manager' => $csrf, 'twig' => $twig];

        return new class($services) implements ContainerInterface {
            /** @param array<string, object> $services */
            public function __construct(private readonly array $services)
            {
            }

            public function get(string $id): object
            {
                return $this->services[$id] ?? throw new \RuntimeException("Service not stubbed: {$id}");
            }

            public function has(string $id): bool
            {
                return isset($this->services[$id]);
            }
        };
    }

    /** @param array<string, mixed> $body */
    private function post(array $body): Request
    {
        return Request::create('/mcp/oauth/agent/identity', 'POST', server: ['REMOTE_ADDR' => '203.0.113.9'], content: json_encode($body, \JSON_THROW_ON_ERROR));
    }

    private function contextFactory(): AgentContextFactoryInterface
    {
        $factory = $this->createStub(AgentContextFactoryInterface::class);
        $factory->method('create')->willReturn(new AgentContext($this->createStub(ChannelInterface::class), 'https://shop.example', 'en_US'));

        return $factory;
    }

    /** @return array<string, mixed> */
    private function json(Response $response): array
    {
        $data = json_decode((string) $response->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertIsArray($data);

        return $data;
    }

    private function attemptToken(string $verificationUri): string
    {
        parse_str((string) parse_url($verificationUri, \PHP_URL_QUERY), $query);

        return (string) $query['claim_attempt_token'];
    }
}
