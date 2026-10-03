<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Koh\SyliusMcpOAuth\Controller\RegisterController;
use Koh\SyliusMcpOAuth\Controller\RevokeController;
use Koh\SyliusMcpOAuth\Controller\TokenController;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The three unauthenticated OAuth endpoints. They are reachable by anyone, so
 * what they refuse matters more than what they return: the token endpoint must
 * not mint a token from a bad grant, and the revocation endpoint must not let a
 * caller learn which tokens exist by watching its answers.
 */
#[CoversClass(TokenController::class)]
#[CoversClass(RegisterController::class)]
#[CoversClass(RevokeController::class)]
final class OAuthEndpointsTest extends TestCase
{
    private const VERIFIER = 'a-verifier-long-enough-to-be-realistic-0123456789';
    private const CLIENT_ID = 'mcpc_abc';
    private const REDIRECT_URI = 'https://client.example/cb';

    // --- token endpoint ------------------------------------------------------

    public function testAValidGrantYieldsABearerToken(): void
    {
        $response = $this->token($this->tokenRequest());

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());

        $body = $this->body($response);
        self::assertSame('Bearer', $body['token_type']);
        self::assertStringStartsWith('tbmcp_', $body['access_token']);
        self::assertSame('mcp', $body['scope']);
    }

    public function testTheDefaultLifetimeIsTheDocumentedHour(): void
    {
        // THR-AGENT-020: the documented default was 3600 s while tokens
        // actually lived 90 days.
        $body = $this->body($this->token($this->tokenRequest()));

        self::assertSame(3600, $body['expires_in']);
    }

    public function testTheConfiguredLifetimeIsAdvertisedAndStored(): void
    {
        // A client caches the token for expires_in seconds. If that disagrees
        // with the stored expiry, the client keeps using a token the server has
        // already stopped accepting — or the server honours one far longer
        // than anyone configured.
        $persisted = null;
        $before = new \DateTimeImmutable();
        $response = $this->token(
            $this->tokenRequest(),
            function (object $entity) use (&$persisted): void {
                if ($entity instanceof McpAccessToken) {
                    $persisted = $entity;
                }
            },
            accessTokenTtl: 900,
        );
        $after = new \DateTimeImmutable();

        self::assertSame(900, $this->body($response)['expires_in']);
        self::assertInstanceOf(McpAccessToken::class, $persisted);

        $expiresAt = $persisted->getExpiresAt();
        self::assertNotNull($expiresAt);
        self::assertGreaterThanOrEqual($before->modify('+900 seconds')->getTimestamp(), $expiresAt->getTimestamp());
        self::assertLessThanOrEqual($after->modify('+900 seconds')->getTimestamp(), $expiresAt->getTimestamp());
    }

    public function testATokenPastItsConfiguredLifetimeIsNoLongerValid(): void
    {
        $persisted = null;
        $this->token(
            $this->tokenRequest(),
            function (object $entity) use (&$persisted): void {
                if ($entity instanceof McpAccessToken) {
                    $persisted = $entity;
                }
            },
            accessTokenTtl: 60,
        );

        self::assertInstanceOf(McpAccessToken::class, $persisted);
        self::assertTrue($persisted->isValid(new \DateTimeImmutable('+30 seconds')));
        self::assertFalse($persisted->isValid(new \DateTimeImmutable('+61 seconds')));
    }

    public function testANonPositiveLifetimeIsRefusedAtConstruction(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new TokenController(0);
    }

    public function testAnUnsupportedGrantTypeIsRefusedWithoutTouchingTheCode(): void
    {
        $response = $this->token($this->tokenRequest(['grant_type' => 'password']));

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('unsupported_grant_type', $this->body($response)['error']);
    }

    public function testAMissingGrantTypeIsRefused(): void
    {
        $request = $this->tokenRequest();
        $request->request->remove('grant_type');

        self::assertSame(Response::HTTP_BAD_REQUEST, $this->token($request)->getStatusCode());
    }

    public function testAFailedExchangeReturnsTheProtocolErrorAndNoToken(): void
    {
        // The OAuth error code is what a client branches on; losing it turns a
        // precise failure into an opaque one.
        $response = $this->token($this->tokenRequest(['code_verifier' => 'wrong']));

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());

        $body = $this->body($response);
        self::assertSame('invalid_grant', $body['error']);
        self::assertArrayNotHasKey('access_token', $body);
    }

    public function testTokenResponsesAreNeverCached(): void
    {
        // A cached token response would hand the same bearer token to whoever
        // shares the cache.
        foreach ([$this->tokenRequest(), $this->tokenRequest(['grant_type' => 'password'])] as $request) {
            self::assertStringContainsString(
                'no-store',
                (string) $this->token($request)->headers->get('Cache-Control'),
            );
        }
    }

    /**
     * No wildcard on an endpoint that mints credentials: a browser-based
     * client must be on the allow-list, and gets its own origin back.
     * Server-side clients send no Origin and are unaffected.
     */
    public function testTheTokenEndpointAnswersOnlyAllowListedOrigins(): void
    {
        self::assertFalse($this->token($this->tokenRequest())->headers->has('Access-Control-Allow-Origin'));

        $request = $this->tokenRequest();
        $request->headers->set('Origin', 'https://inspector.example');
        $response = $this->token($request, cors: new CorsPolicy(['https://inspector.example']));
        self::assertSame('https://inspector.example', $response->headers->get('Access-Control-Allow-Origin'));
        self::assertSame('Origin', $response->headers->get('Vary'));

        $request = $this->tokenRequest();
        $request->headers->set('Origin', 'https://evil.example');
        self::assertFalse($this->token($request, cors: new CorsPolicy(['https://inspector.example']))->headers->has('Access-Control-Allow-Origin'));
    }

    public function testTheMintedTokenIsBoundToTheConsentingAdmin(): void
    {
        $persisted = null;
        $response = $this->token($this->tokenRequest(), function (object $entity) use (&$persisted): void {
            if ($entity instanceof McpAccessToken) {
                $persisted = $entity;
            }
        });

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInstanceOf(McpAccessToken::class, $persisted);
        // 7 is the admin who consented at /authorize, carried on the code.
        self::assertSame(7, $persisted->getAdminUserId());
        self::assertSame(self::CLIENT_ID, $persisted->getClientId());
    }

    // --- registration endpoint ----------------------------------------------

    public function testRegistrationReturns201WithAClientIdentifier(): void
    {
        $response = $this->register([
            'client_name' => 'My Client',
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        self::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        self::assertFalse($response->headers->has('Access-Control-Allow-Origin'), 'no wildcard');

        $body = $this->body($response);
        self::assertStringStartsWith('mcpc_', $body['client_id']);
        self::assertSame(['code'], $body['response_types']);
    }

    /**
     * The rest of the RFC 7591 response body: what the endpoint returns beyond
     * the client_id and the redirect_uris that are already exercised elsewhere.
     */
    public function testRegistrationResponseCarriesTheFullClientRecord(): void
    {
        $before = time();
        $body = $this->body($this->register([
            'client_name' => 'My Client',
            'redirect_uris' => [self::REDIRECT_URI],
        ]));

        self::assertSame('My Client', $body['client_name']);
        self::assertSame(['authorization_code'], $body['grant_types']);
        self::assertSame('none', $body['token_endpoint_auth_method']);
        self::assertGreaterThanOrEqual($before, $body['client_id_issued_at']);
        self::assertLessThanOrEqual(time(), $body['client_id_issued_at']);
    }

    /** RFC 7591 does not require client_name; the server names the client itself. */
    public function testRegistrationWithoutAClientNameFallsBackToAPlaceholder(): void
    {
        $body = $this->body($this->register(['redirect_uris' => [self::REDIRECT_URI]]));

        self::assertSame('MCP Client', $body['client_name']);
    }

    /**
     * A failed registration must name why, not just that it failed — the
     * description is what a client-side developer actually acts on.
     */
    public function testARefusedRegistrationCarriesTheErrorDescription(): void
    {
        $body = $this->body($this->register([
            'client_name' => 'Evil',
            'redirect_uris' => ['javascript:alert(1)'],
        ]));

        self::assertSame(
            'Scheme "javascript" is not allowed for a redirect_uri.',
            $body['error_description'],
        );
    }

    public function testRegistrationRefusesAnUnusableRedirectUri(): void
    {
        // Registration is open, so this is the only place a hostile redirect
        // target can be turned away before it is echoed into a Location header.
        $response = $this->register([
            'client_name' => 'Evil',
            'redirect_uris' => ['javascript:alert(1)'],
        ]);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_redirect_uri', $this->body($response)['error']);
    }

    public function testRegistrationRefusesAWellFormedUriThatIsNotAllowListed(): void
    {
        // THR-AGENT-014: consent phishing needs nothing more than a client whose
        // HTTPS redirect points at the attacker. The response must be the RFC
        // 7591 error, not a client_id.
        $response = $this->register([
            'client_name' => 'Looks Legit',
            'redirect_uris' => ['https://attacker.example/cb'],
        ]);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $body = $this->body($response);
        self::assertSame('invalid_redirect_uri', $body['error']);
        self::assertArrayNotHasKey('client_id', $body);
    }

    public function testRegistrationRefusesABodyWithNoRedirectUris(): void
    {
        $response = $this->register(['client_name' => 'My Client']);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_client_metadata', $this->body($response)['error']);
    }

    public function testRegistrationSurvivesAMalformedBody(): void
    {
        // An unparseable body must produce the protocol error, not a 500.
        $response = $this->registerRaw('not json at all');

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    public function testRegistrationIgnoresNonStringRedirectUriEntries(): void
    {
        // Entries that are objects or numbers are dropped rather than cast, so
        // a caller cannot smuggle a structure past the URI validation.
        $response = $this->register([
            'client_name' => 'My Client',
            'redirect_uris' => [self::REDIRECT_URI, 42, ['nested' => true]],
        ]);

        self::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        self::assertSame([self::REDIRECT_URI], $this->body($response)['redirect_uris']);
    }

    /**
     * The filtered list must be re-indexed from 0, not just non-empty.
     *
     * Dropping the leading non-string entries without re-indexing would leave
     * the surviving URI at key 1, which json_encode()s as a JSON *object*
     * (`{"1":"…"}`), not the array an OAuth client expects for redirect_uris.
     */
    public function testRegistrationReindexesTheRedirectUrisAfterDroppingLeadingNonStringEntries(): void
    {
        $body = $this->body($this->register([
            'client_name' => 'My Client',
            'redirect_uris' => [42, ['nested' => true], self::REDIRECT_URI],
        ]));

        self::assertSame([self::REDIRECT_URI], $body['redirect_uris']);
    }

    public function testRegistrationRefusesARedirectUrisFieldThatIsNotAList(): void
    {
        $response = $this->register([
            'client_name' => 'My Client',
            'redirect_uris' => 'https://client.example/cb',
        ]);

        self::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
    }

    // --- revocation endpoint -------------------------------------------------

    public function testRevocationAnswers200ForAKnownToken(): void
    {
        $token = new McpAccessToken(hash('sha256', 'x'), 7, 'laptop');

        $response = $this->revoke('tbmcp_' . str_repeat('a', 64), $token);

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertTrue($token->isRevoked());
    }

    public function testRevocationAnswers200ForAnUnknownTokenToo(): void
    {
        // RFC 7009. Differing answers would let a caller probe which tokens
        // exist without ever holding a valid one.
        $known = $this->revoke('tbmcp_' . str_repeat('a', 64), new McpAccessToken(hash('sha256', 'x'), 7, 'l'));
        $unknown = $this->revoke('tbmcp_' . str_repeat('b', 64), null);

        self::assertSame($known->getStatusCode(), $unknown->getStatusCode());
        self::assertSame(Response::HTTP_OK, $unknown->getStatusCode());
    }

    public function testRevocationAnswers200ForAnAbsentTokenField(): void
    {
        self::assertSame(Response::HTTP_OK, $this->revoke(null, null)->getStatusCode());
    }

    public function testTheRevocationEndpointSendsNoWildcard(): void
    {
        self::assertFalse($this->revoke('tbmcp_' . str_repeat('a', 64), null)->headers->has('Access-Control-Allow-Origin'));
    }

    // --- helpers -------------------------------------------------------------

    /**
     * @return array<string, mixed>
     */
    private function body(JsonResponse $response): array
    {
        $decoded = json_decode((string) $response->getContent(), true);

        return \is_array($decoded) ? $decoded : [];
    }

    private function challenge(): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '=');
    }

    /**
     * @param array<string, string> $overrides
     */
    private function tokenRequest(array $overrides = []): Request
    {
        return new Request(request: array_merge([
            'grant_type' => 'authorization_code',
            'code' => 'raw-code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::VERIFIER,
        ], $overrides));
    }

    private function token(Request $request, ?\Closure $persistCallback = null, ?int $accessTokenTtl = null, ?CorsPolicy $cors = null): JsonResponse
    {
        $entityManager = $this->entityManager($persistCallback);
        $controller = new TokenController($accessTokenTtl ?? TokenController::DEFAULT_ACCESS_TOKEN_TTL, corsPolicy: $cors ?? new CorsPolicy());

        $response = $controller(
            $request,
            new OAuthServer($entityManager, null, new RedirectUriPolicy([self::REDIRECT_URI])),
            new AccessTokenManager($entityManager),
        );
        self::assertInstanceOf(JsonResponse::class, $response);

        return $response;
    }

    /**
     * @param array<string, mixed> $body
     */
    private function register(array $body): JsonResponse
    {
        return $this->registerRaw(json_encode($body, \JSON_THROW_ON_ERROR));
    }

    private function registerRaw(string $content): JsonResponse
    {
        $response = (new RegisterController())(
            new Request(content: $content),
            new OAuthServer($this->entityManager(), null, new RedirectUriPolicy([self::REDIRECT_URI])),
        );
        self::assertInstanceOf(JsonResponse::class, $response);

        return $response;
    }

    private function revoke(?string $rawToken, ?McpAccessToken $token): JsonResponse
    {
        $tokens = $this->createStub(EntityRepository::class);
        $tokens->method('findOneBy')->willReturn($token);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($tokens);

        return (new RevokeController())(
            new Request(request: $rawToken === null ? [] : ['token' => $rawToken]),
            new AccessTokenManager($entityManager),
        );
    }

    private function entityManager(?\Closure $persistCallback = null): EntityManagerInterface
    {
        $code = new McpAuthorizationCode(
            codeHash: hash('sha256', 'raw-code'),
            clientId: self::CLIENT_ID,
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $this->challenge(),
            codeChallengeMethod: 'S256',
            expiresAt: (new \DateTimeImmutable())->modify('+300 seconds'),
        );

        $codes = $this->createStub(EntityRepository::class);
        $codes->method('findOneBy')->willReturn($code);

        $clients = $this->createStub(EntityRepository::class);
        $clients->method('findOneBy')->willReturn(
            new McpOAuthClient(self::CLIENT_ID, 'My Client', [self::REDIRECT_URI]),
        );

        $query = $this->createStub(Query::class);
        $query->method('setParameter')->willReturnSelf();
        $query->method('execute')->willReturn(1);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturnCallback(
            static fn (string $class): EntityRepository => McpAuthorizationCode::class === $class ? $codes : $clients,
        );
        $entityManager->method('createQuery')->willReturn($query);

        if ($persistCallback !== null) {
            $entityManager->method('persist')->willReturnCallback($persistCallback);
        }

        return $entityManager;
    }
}
