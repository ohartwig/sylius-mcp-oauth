<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth token endpoint (RFC 6749 §4.1.3, §6). Exchanges an authorization code
 * + PKCE verifier — or a refresh token — for an MCP access token bound to the
 * admin user who consented. Public clients only, so no client authentication:
 * PKCE is the proof for a code, rotation the safeguard for a refresh token.
 *
 * The access token lives `koh_mcp_oauth.access_token_ttl` seconds, and
 * `expires_in` says exactly that: a client caches the token for expires_in, so
 * the two must never disagree. With `refresh_token_ttl` above zero a refresh
 * token comes along; each refresh spends it and hands out a new one
 * ({@see RefreshTokenManager}).
 *
 * The token is bound to the resource of the authorization (RFC 8707). A
 * `resource` parameter here must name the same resource, or the request fails
 * with invalid_target.
 */
final class TokenController extends AbstractController
{
    /** Matches the bundle configuration default. */
    public const DEFAULT_ACCESS_TOKEN_TTL = 3600;

    public function __construct(
        private readonly int $accessTokenTtl = self::DEFAULT_ACCESS_TOKEN_TTL,
        private readonly int $refreshTokenTtl = 0,
        private readonly ?RefreshTokenManager $refreshTokens = null,
        private readonly ?ResourceIndicator $resource = null,
        private readonly EndpointRateLimiter $rateLimiter = new EndpointRateLimiter(),
        private readonly CorsPolicy $corsPolicy = new CorsPolicy(),
    ) {
        if ($accessTokenTtl < 1) {
            throw new \InvalidArgumentException('access_token_ttl must be a positive number of seconds.');
        }
        if ($refreshTokenTtl < 0) {
            throw new \InvalidArgumentException('refresh_token_ttl must be zero (off) or a positive number of seconds.');
        }
    }

    public function __invoke(Request $request, OAuthServer $server, AccessTokenManager $tokens): Response
    {
        $limited = $this->rateLimiter->check('token', $request);
        if (null !== $limited) {
            return $this->corsPolicy->apply($request, $limited);
        }

        $grantType = (string) $request->request->get('grant_type', '');

        try {
            $grant = match ($grantType) {
                'authorization_code' => $this->authorizationCode($request, $server),
                'refresh_token' => $this->refresh($request),
                default => throw new OAuthException('unsupported_grant_type', null === $this->refreshTokens || 0 === $this->refreshTokenTtl
                    ? 'Only authorization_code is supported.'
                    : 'Only authorization_code and refresh_token are supported.'),
            };
        } catch (OAuthException $e) {
            return $this->fail($request, $e->error, $e->getMessage());
        }

        $expiresAt = (new \DateTimeImmutable())->modify(\sprintf('+%d seconds', $this->accessTokenTtl));

        $result = $tokens->create(
            adminUserId: $grant['admin_user_id'],
            name: $grant['name'],
            scopes: $grant['scopes'],
            expiresAt: $expiresAt,
            clientId: $grant['client_id'],
            audience: $grant['resource'],
            refreshFamily: $grant['family'],
            ip: $request->getClientIp(),
        );

        $body = [
            'access_token' => $result['token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->accessTokenTtl,
            'scope' => implode(' ', $grant['scopes']),
        ];

        if (null !== $this->refreshTokens && $this->refreshTokenTtl > 0 && null !== $grant['family']) {
            $body['refresh_token'] = $this->refreshTokens->issue(
                $grant['family'],
                $grant['admin_user_id'],
                $grant['client_id'],
                $grant['scopes'],
                $grant['resource'],
                $this->refreshTokenTtl,
            )['token'];
        }

        return $this->cors($request, new JsonResponse($body));
    }

    /**
     * @return array{admin_user_id: int, name: string, scopes: list<string>, client_id: string, resource: string|null, family: string|null}
     */
    private function authorizationCode(Request $request, OAuthServer $server): array
    {
        $payload = $server->consumeCode(
            rawCode: (string) $request->request->get('code', ''),
            clientId: (string) $request->request->get('client_id', ''),
            redirectUri: (string) $request->request->get('redirect_uri', ''),
            codeVerifier: (string) $request->request->get('code_verifier', ''),
        );

        $this->assertResource($request, $payload['resource']);

        return [
            'admin_user_id' => $payload['admin_user_id'],
            'name' => $payload['client']->getClientName(),
            'scopes' => $payload['scopes'],
            'client_id' => $payload['client']->getClientId(),
            'resource' => $payload['resource'],
            'family' => null !== $this->refreshTokens && $this->refreshTokenTtl > 0 ? RefreshTokenManager::newFamily() : null,
        ];
    }

    /**
     * @return array{admin_user_id: int, name: string, scopes: list<string>, client_id: string, resource: string|null, family: string|null}
     */
    private function refresh(Request $request): array
    {
        if (null === $this->refreshTokens || 0 === $this->refreshTokenTtl) {
            throw new OAuthException('unsupported_grant_type', 'Only authorization_code is supported.');
        }

        $clientId = (string) $request->request->get('client_id', '');
        $spent = $this->refreshTokens->rotate((string) $request->request->get('refresh_token', ''), $clientId);
        $this->assertResource($request, $spent->getAudience());

        // RFC 6749 §6: a refresh may narrow the scope, never widen it.
        $scopes = $spent->getScopes();
        $requested = trim((string) $request->request->get('scope', ''));
        if ('' !== $requested) {
            $narrowed = array_values(array_filter(explode(' ', $requested), static fn (string $s): bool => '' !== $s));
            if ([] !== array_diff($narrowed, $scopes)) {
                throw new OAuthException('invalid_scope', 'A refresh cannot add scopes the authorization did not grant.');
            }
            $scopes = $narrowed;
        }

        return [
            'admin_user_id' => $spent->getAdminUserId(),
            'name' => $clientId,
            'scopes' => $scopes,
            'client_id' => $clientId,
            'resource' => $spent->getAudience(),
            'family' => $spent->getFamily(),
        ];
    }

    private function assertResource(Request $request, ?string $bound): void
    {
        $requested = (string) $request->request->get('resource', '');
        if ('' === $requested) {
            return;
        }

        $matches = null !== $bound
            ? rtrim(strtolower($requested), '/') === rtrim(strtolower($bound), '/')
            : (null === $this->resource || $this->resource->matches($requested, $request));
        if (!$matches) {
            throw new OAuthException('invalid_target', 'The resource does not match the one this grant was issued for.');
        }
    }

    private function fail(Request $request, string $error, string $description): JsonResponse
    {
        return $this->cors($request, new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            Response::HTTP_BAD_REQUEST,
        ));
    }

    private function cors(Request $request, JsonResponse $response): JsonResponse
    {
        $this->corsPolicy->apply($request, $response);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
