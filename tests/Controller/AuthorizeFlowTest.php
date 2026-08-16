<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Controller\AuthorizeController;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * The consent endpoint is the only place an admin's session is turned into an
 * authorization code. Its sharpest edge is the redirect: anything echoed into a
 * Location header before the client is validated is an open redirect, and in
 * this protocol an open redirect is a code-delivery mechanism for an attacker.
 * The order of the checks is therefore part of the behaviour, not a detail.
 */
#[CoversClass(AuthorizeController::class)]
final class AuthorizeFlowTest extends TestCase
{
    private const CLIENT_ID = 'mcpc_abc';
    private const REDIRECT_URI = 'https://client.example/cb';
    private const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    public function testAnUnknownClientGetsAnOnSiteErrorRatherThanARedirect(): void
    {
        // Redirecting here would echo an attacker-chosen URI before anything
        // about it has been checked.
        $response = $this->authorize($this->query(['client_id' => 'mcpc_unknown']), clientExists: false);

        self::assertNotInstanceOf(RedirectResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testARedirectUriTheClientNeverRegisteredGetsAnOnSiteError(): void
    {
        // The registered set is the whole defence: without this check a caller
        // could name any destination and have the code delivered there.
        $response = $this->authorize($this->query(['redirect_uri' => 'https://attacker.example/steal']));

        self::assertNotInstanceOf(RedirectResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testTheOnSiteErrorDoesNotReflectTheSubmittedUri(): void
    {
        // The rejected URI must not come back in the page either, or the error
        // page becomes the injection point instead of the Location header.
        $response = $this->authorize($this->query([
            'redirect_uri' => 'https://attacker.example/"><script>alert(1)</script>',
        ]));

        self::assertStringNotContainsString('<script>', (string) $response->getContent());
        self::assertStringNotContainsString('attacker.example', (string) $response->getContent());
    }

    public function testAMissingCodeChallengeIsRefused(): void
    {
        // PKCE is mandatory. Issuing a code without a challenge would make an
        // intercepted redirect sufficient to obtain a token.
        $response = $this->authorize($this->query(['code_challenge' => '']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=invalid_request', $response->getTargetUrl());
    }

    public function testAChallengeMethodOtherThanS256IsRefused(): void
    {
        // "plain" would put the verifier in the same redirect as the code.
        $response = $this->authorize($this->query(['code_challenge_method' => 'plain']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=invalid_request', $response->getTargetUrl());
    }

    public function testAnUnsupportedResponseTypeIsRefused(): void
    {
        $response = $this->authorize($this->query(['response_type' => 'token']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=unsupported_response_type', $response->getTargetUrl());
    }

    public function testAnUnsupportedScopeIsRefused(): void
    {
        $response = $this->authorize($this->query(['scope' => 'mcp admin']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=invalid_scope', $response->getTargetUrl());
    }

    public function testProtocolErrorsCarryTheStateBack(): void
    {
        // Without state the client cannot tie the answer to its own request,
        // which is the CSRF defence on the client side of the flow.
        $response = $this->authorize($this->query(['response_type' => 'token', 'state' => 'xyz789']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('state=xyz789', $response->getTargetUrl());
    }

    public function testAnUnauthenticatedRequestDoesNotIssueACode(): void
    {
        $response = $this->authorize($this->query(), authenticated: false);

        self::assertNotInstanceOf(RedirectResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testAGetRequestRendersTheConsentScreenWithoutIssuingACode(): void
    {
        // Merely visiting the URL must not authorise anything; a code issued on
        // GET would be obtainable by making an admin load an image.
        $persisted = [];
        $response = $this->authorize($this->query(), persisted: $persisted);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertNotInstanceOf(RedirectResponse::class, $response);
        self::assertSame([], $persisted);
    }

    /**
     * The template is stubbed in every other test, which hides whether the
     * consent screen actually receives what it needs to render the client's
     * identity and to re-submit the same request as the POST. Losing either
     * silently breaks the page rather than the protocol.
     */
    public function testTheConsentScreenReceivesTheClientAndTheOriginalRequestParameters(): void
    {
        $renderContext = null;
        $this->authorize($this->query(), renderContext: $renderContext);

        self::assertIsArray($renderContext);
        self::assertArrayHasKey('client', $renderContext);
        self::assertInstanceOf(McpOAuthClient::class, $renderContext['client']);
        self::assertSame(self::CLIENT_ID, $renderContext['client']->getClientId());

        self::assertArrayHasKey('query', $renderContext);
        self::assertSame(self::CLIENT_ID, $renderContext['query']['client_id']);
        self::assertSame(self::REDIRECT_URI, $renderContext['query']['redirect_uri']);
    }

    /**
     * When the admin has an email, the consent screen must show *the email*,
     * not merely some identifying string — the two happen to be equal for the
     * default test admin, which is exactly what let a swapped branch here go
     * unnoticed.
     */
    public function testTheConsentScreenShowsTheAdminsEmailRatherThanTheBareIdentifier(): void
    {
        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getId')->willReturn(99);
        $admin->method('getEmail')->willReturn('admin@example.test');
        $admin->method('getUserIdentifier')->willReturn('ohartwig');

        $renderContext = null;
        $this->authorize($this->query(), admin: $admin, renderContext: $renderContext);

        self::assertIsArray($renderContext);
        self::assertSame('admin@example.test', $renderContext['admin_label']);
    }

    public function testApprovingIssuesACodeAndRedirectsBackToTheClient(): void
    {
        $response = $this->authorize($this->postRequest(['decision' => 'approve']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringStartsWith(self::REDIRECT_URI . '?', $response->getTargetUrl());
        self::assertStringContainsString('code=', $response->getTargetUrl());
        self::assertStringNotContainsString('error=', $response->getTargetUrl());
    }

    public function testTheIssuedCodeIsBoundToTheLoggedInAdmin(): void
    {
        // The code carries the identity the token will be minted for, so binding
        // it to anyone but the admin who consented would be a privilege swap.
        $persisted = [];
        $this->authorize($this->postRequest(['decision' => 'approve']), persisted: $persisted);

        $codes = array_values(array_filter(
            $persisted,
            static fn (object $e): bool => $e instanceof McpAuthorizationCode,
        ));

        self::assertCount(1, $codes);
        self::assertSame(99, $codes[0]->getAdminUserId());
        self::assertSame(self::REDIRECT_URI, $codes[0]->getRedirectUri());
        self::assertSame(self::CHALLENGE, $codes[0]->getCodeChallenge());
    }

    public function testApprovalCarriesTheStateBack(): void
    {
        $response = $this->authorize($this->postRequest(['decision' => 'approve', 'state' => 'xyz789']));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('state=xyz789', $response->getTargetUrl());
    }

    public function testDecliningIssuesNoCodeAndReportsAccessDenied(): void
    {
        $persisted = [];
        $response = $this->authorize($this->postRequest(['decision' => 'deny']), persisted: $persisted);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=access_denied', $response->getTargetUrl());
        self::assertStringNotContainsString('code=', $response->getTargetUrl());
        self::assertSame([], $persisted);
    }

    public function testAnAbsentDecisionIsTreatedAsRefusal(): void
    {
        // Anything that is not an explicit approval must not authorise.
        $response = $this->authorize($this->postRequest([]));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('error=access_denied', $response->getTargetUrl());
    }

    public function testApprovalWithoutAValidCsrfTokenIssuesNoCode(): void
    {
        // Without this, a cross-site form could make a logged-in admin authorise
        // an attacker's client silently.
        $persisted = [];
        $response = $this->authorize(
            $this->postRequest(['decision' => 'approve']),
            csrfValid: false,
            persisted: $persisted,
        );

        self::assertNotInstanceOf(RedirectResponse::class, $response);
        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        self::assertSame([], $persisted);
    }

    public function testAnExistingQueryOnTheRedirectUriIsPreserved(): void
    {
        $uri = 'https://client.example/cb?tenant=de';
        $response = $this->authorize(
            $this->postRequest(['decision' => 'approve', 'redirect_uri' => $uri]),
            registeredRedirectUri: $uri,
        );

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringContainsString('tenant=de', $response->getTargetUrl());
        self::assertStringContainsString('&code=', $response->getTargetUrl());
    }

    // --- helpers -------------------------------------------------------------

    /**
     * @param array<string, string> $overrides
     *
     * @return array<string, string>
     */
    private function params(array $overrides = []): array
    {
        return array_merge([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'response_type' => 'code',
            'scope' => 'mcp',
            'code_challenge' => self::CHALLENGE,
            'code_challenge_method' => 'S256',
            'state' => '',
        ], $overrides);
    }

    /**
     * @param array<string, string> $overrides
     */
    private function query(array $overrides = []): Request
    {
        return new Request(query: $this->params($overrides));
    }

    /**
     * @param array<string, string> $overrides
     */
    private function postRequest(array $overrides = []): Request
    {
        $request = new Request(request: $this->params($overrides) + ['_csrf_token' => 'valid']);
        $request->setMethod('POST');

        return $request;
    }

    /**
     * @param array<object>             $persisted
     * @param array<string, mixed>|null $renderContext
     */
    private function authorize(
        Request $request,
        bool $clientExists = true,
        ?AdminUserInterface $admin = null,
        bool $authenticated = true,
        bool $csrfValid = true,
        string $registeredRedirectUri = self::REDIRECT_URI,
        array &$persisted = [],
        ?array &$renderContext = null,
    ): Response {
        $clients = $this->createStub(EntityRepository::class);
        $clients->method('findOneBy')->willReturn(
            $clientExists ? new McpOAuthClient(self::CLIENT_ID, 'My Client', [$registeredRedirectUri]) : null,
        );

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($clients);
        $entityManager->method('persist')->willReturnCallback(
            function (object $entity) use (&$persisted): void {
                $persisted[] = $entity;
            },
        );

        $controller = new AuthorizeController();
        $controller->setContainer($this->container(
            $authenticated ? ($admin ?? $this->admin()) : null,
            $csrfValid,
            $renderContext,
        ));

        return $controller($request, new OAuthServer($entityManager));
    }

    private function admin(int $id = 99): AdminUserInterface
    {
        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getId')->willReturn($id);
        $admin->method('getEmail')->willReturn('admin@example.test');
        $admin->method('getUserIdentifier')->willReturn('admin@example.test');

        return $admin;
    }

    /** @param array<string, mixed>|null $renderContext */
    private function container(?AdminUserInterface $admin, bool $csrfValid, ?array &$renderContext = null): ContainerInterface
    {
        $tokenStorage = $this->createStub(TokenStorageInterface::class);
        if ($admin !== null) {
            $securityToken = $this->createStub(TokenInterface::class);
            $securityToken->method('getUser')->willReturn($admin);
            $tokenStorage->method('getToken')->willReturn($securityToken);
        } else {
            $tokenStorage->method('getToken')->willReturn(null);
        }

        $csrf = $this->createStub(CsrfTokenManagerInterface::class);
        $csrf->method('isTokenValid')->willReturn($csrfValid);

        $twig = $this->createStub(Environment::class);
        $twig->method('render')->willReturnCallback(
            function (string $name, array $context) use (&$renderContext): string {
                $renderContext = $context;

                return '<html>consent</html>';
            },
        );

        $services = [
            'security.token_storage' => $tokenStorage,
            'security.csrf.token_manager' => $csrf,
            'twig' => $twig,
        ];

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
}
