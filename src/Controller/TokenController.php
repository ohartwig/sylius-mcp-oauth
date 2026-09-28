<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth token endpoint (RFC 6749 §4.1.3). Exchanges an authorization code +
 * PKCE verifier for an MCP access token bound to the admin user who consented.
 * Public clients only, so no client authentication — PKCE is the proof.
 *
 * The token lives `koh_mcp_oauth.access_token_ttl` seconds, and `expires_in`
 * says exactly that: a client caches the token for expires_in, so the two must
 * never disagree. No refresh token is issued; when the token expires the client
 * runs the authorization flow again.
 */
final class TokenController extends AbstractController
{
    /** Matches the bundle configuration default. */
    public const DEFAULT_ACCESS_TOKEN_TTL = 3600;

    public function __construct(
        private readonly int $accessTokenTtl = self::DEFAULT_ACCESS_TOKEN_TTL,
    ) {
        if ($accessTokenTtl < 1) {
            throw new \InvalidArgumentException('access_token_ttl must be a positive number of seconds.');
        }
    }

    public function __invoke(Request $request, OAuthServer $server, AccessTokenManager $tokens): JsonResponse
    {
        $grantType = (string) $request->request->get('grant_type', '');
        if ($grantType !== 'authorization_code') {
            return $this->fail('unsupported_grant_type', 'Only authorization_code is supported.');
        }

        try {
            $payload = $server->consumeCode(
                rawCode: (string) $request->request->get('code', ''),
                clientId: (string) $request->request->get('client_id', ''),
                redirectUri: (string) $request->request->get('redirect_uri', ''),
                codeVerifier: (string) $request->request->get('code_verifier', ''),
            );
        } catch (OAuthException $e) {
            return $this->fail($e->error, $e->getMessage());
        }

        $expiresAt = (new \DateTimeImmutable())->modify(\sprintf('+%d seconds', $this->accessTokenTtl));

        $result = $tokens->create(
            adminUserId: $payload['admin_user_id'],
            name: $payload['client']->getClientName(),
            scopes: $payload['scopes'],
            expiresAt: $expiresAt,
            clientId: $payload['client']->getClientId(),
        );

        return $this->cors(new JsonResponse([
            'access_token' => $result['token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->accessTokenTtl,
            'scope' => implode(' ', $payload['scopes']),
        ]));
    }

    private function fail(string $error, string $description): JsonResponse
    {
        return $this->cors(new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            Response::HTTP_BAD_REQUEST,
        ));
    }

    private function cors(JsonResponse $response): JsonResponse
    {
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
