<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusAgentContracts\Http\AgentJsonResponder;
use Koh\SyliusAgentContracts\Registry\AuthMethodRegistry;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * OAuth discovery documents, fetched unauthenticated by MCP clients:
 *  - RFC 8414 Authorization Server Metadata (/.well-known/oauth-authorization-server)
 *  - RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource,
 *    and path-inserted at /.well-known/oauth-protected-resource/_mcp)
 *
 * URLs come from the AgentContext rather than the request. TLS commonly
 * terminates at an ingress, and without framework.trusted_proxies the request
 * reports the internal host — which in an issuer is not cosmetic: a client that
 * compares the issuer against the one it discovered rejects the token.
 */
final class MetadataController
{
    public function __construct(
        private readonly AgentContextFactoryInterface $contextFactory,
        private readonly AuthMethodRegistry $authMethods,
        private readonly AgentJsonResponder $responder,
        private readonly string $resourcePath = '/_mcp',
        private readonly bool $refreshTokens = false,
        private readonly bool $agentRegistration = false,
    ) {
    }

    public function authorizationServer(Request $request): Response
    {
        $context = $this->contextFactory->create();

        $metadata = [
            'issuer' => $context->baseUrl,
            'authorization_endpoint' => $context->url('/admin/mcp/authorize'),
            'token_endpoint' => $context->url('/mcp/oauth/token'),
            'registration_endpoint' => $context->url('/mcp/oauth/register'),
            'revocation_endpoint' => $context->url('/mcp/oauth/revoke'),
            'response_types_supported' => ['code'],
            'grant_types_supported' => $this->grantTypes(),
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => OAuthServer::SUPPORTED_SCOPES,
        ];

        // Aggregated across every installed auth method, so a shop offering
        // OAuth and, say, Web Bot Auth advertises both without this bundle
        // knowing the other exists.
        $agentAuth = $this->authMethods->toAgentAuth($context);
        if ([] !== $agentAuth) {
            $metadata['agent_auth'] = $agentAuth;
        }

        return $this->responder->respond($metadata, maxAge: 300, request: $request);
    }

    /** @return list<string> */
    private function grantTypes(): array
    {
        $types = ['authorization_code'];
        if ($this->refreshTokens) {
            $types[] = 'refresh_token';
        }
        // auth.md: jwt-bearer exchanges the identity assertion, the claim
        // grant is how an agent polls for the end of the claim ceremony.
        if ($this->agentRegistration) {
            $types[] = TokenController::GRANT_JWT_BEARER;
            $types[] = TokenController::GRANT_AGENT_CLAIM;
        }

        return $types;
    }

    /**
     * The path-inserted location of RFC 9728 §3.1, for the one resource this
     * server guards.
     *
     * Only the configured resource path answers. Anything else is a 404 rather
     * than a fallback to the same document: metadata served under
     * /.well-known/oauth-protected-resource/de_DE/ would claim, per §3.3, that
     * the storefront page is a protected resource, and a client validating the
     * `resource` member against the URL it asked for rejects it anyway.
     */
    public function protectedResourceAtPath(Request $request, string $resource): Response
    {
        if ('/'.ltrim($resource, '/') !== '/'.ltrim($this->resourcePath, '/')) {
            throw new NotFoundHttpException('No protected resource is described at this path.');
        }

        return $this->protectedResource($request);
    }

    public function protectedResource(Request $request): Response
    {
        $context = $this->contextFactory->create();

        return $this->responder->respond([
            'resource' => $context->url($this->resourcePath),
            'authorization_servers' => [$context->baseUrl],
            'scopes_supported' => OAuthServer::SUPPORTED_SCOPES,
            'bearer_methods_supported' => ['header'],
            'resource_documentation' => $context->url('/auth.md'),
        ], maxAge: 300, request: $request);
    }
}
