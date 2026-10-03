<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth 2.0 Dynamic Client Registration (RFC 7591). An MCP client POSTs its
 * name + redirect URIs and receives a client_id. Public clients only (PKCE, no
 * secret), so registration is open — the code + PKCE + admin login at /authorize
 * are what actually gate access. Open, but rate-limited per address, so one
 * script cannot fill the client table.
 */
final class RegisterController extends AbstractController
{
    public function __construct(
        private readonly EndpointRateLimiter $rateLimiter = new EndpointRateLimiter(),
        private readonly CorsPolicy $corsPolicy = new CorsPolicy(),
    ) {
    }

    public function __invoke(Request $request, OAuthServer $server): Response
    {
        $limited = $this->rateLimiter->check('register', $request);
        if (null !== $limited) {
            return $this->corsPolicy->apply($request, $limited);
        }

        $decoded = json_decode($request->getContent(), true);
        /** @var array<string, mixed> $body */
        $body = \is_array($decoded) ? $decoded : [];

        $redirectUris = $body['redirect_uris'] ?? [];
        if (!\is_array($redirectUris)) {
            $redirectUris = [];
        }

        try {
            $client = $server->registerClient(
                clientName: (string) ($body['client_name'] ?? ''),
                redirectUris: array_values(array_filter($redirectUris, 'is_string')),
            );
        } catch (OAuthException $e) {
            return $this->cors($request, new JsonResponse(
                ['error' => $e->error, 'error_description' => $e->getMessage()],
                Response::HTTP_BAD_REQUEST,
            ));
        }

        return $this->cors($request, new JsonResponse([
            'client_id' => $client->getClientId(),
            'client_id_issued_at' => $client->getCreatedAt()->getTimestamp(),
            'client_name' => $client->getClientName(),
            'redirect_uris' => $client->getRedirectUris(),
            'grant_types' => $client->getGrantTypes(),
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $client->getTokenEndpointAuthMethod(),
        ], Response::HTTP_CREATED));
    }

    private function cors(Request $request, JsonResponse $response): JsonResponse
    {
        $this->corsPolicy->apply($request, $response);

        return $response;
    }
}
