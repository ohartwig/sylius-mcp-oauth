<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusAgentContracts\Http\AgentJsonResponder;
use Koh\SyliusAgentContracts\Registry\AuthMethodRegistry;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth discovery documents, fetched unauthenticated by MCP clients:
 *  - RFC 8414 Authorization Server Metadata (/.well-known/oauth-authorization-server)
 *  - RFC 9728 Protected Resource Metadata (/.well-known/oauth-protected-resource)
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
            'grant_types_supported' => ['authorization_code'],
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
