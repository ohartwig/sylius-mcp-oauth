<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Model\AgentEndpoint;
use Koh\SyliusAgentContracts\Model\ApiCatalogEntry;
use Koh\SyliusAgentContracts\Model\LinkTarget;
use Koh\SyliusAgentContracts\Provider\AgentEndpointProviderInterface;
use Koh\SyliusAgentContracts\Provider\ApiCatalogEntryProviderInterface;

/**
 * Announces the two OAuth metadata documents to llms.txt and the api-catalog.
 */
final class OAuthEndpointProvider implements AgentEndpointProviderInterface, ApiCatalogEntryProviderInterface
{
    public function __construct(private readonly string $resourcePath = '/_mcp')
    {
    }

    public function getAgentEndpoints(AgentContext $context): iterable
    {
        yield new AgentEndpoint(
            path: '/.well-known/oauth-authorization-server',
            title: 'OAuth Authorization Server Metadata',
            protocol: 'oauth2',
            description: 'RFC 8414 — where to register, authorise and exchange tokens.',
        );

        yield new AgentEndpoint(
            path: '/.well-known/oauth-protected-resource',
            title: 'OAuth Protected Resource Metadata',
            protocol: 'oauth2',
            description: 'RFC 9728 — which authorization server guards the MCP endpoint.',
        );
    }

    public function getApiCatalogEntries(AgentContext $context): iterable
    {
        yield new ApiCatalogEntry(
            anchor: $context->url($this->resourcePath),
            serviceDesc: [new LinkTarget(
                $context->url('/.well-known/oauth-protected-resource'),
                'application/json',
            )],
            serviceDoc: [new LinkTarget($context->url('/auth.md'), 'text/markdown')],
            title: 'MCP endpoint (OAuth 2.1 protected)',
        );
    }
}
