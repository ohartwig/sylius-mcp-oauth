<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Model\AuthMethodDescriptor;
use Koh\SyliusAgentContracts\Provider\AuthMethodDescriptorInterface;

/**
 * Describes the OAuth path once, for both /auth.md and the agent_auth block.
 *
 * `identity_types_supported` says `identity_assertion`, not the more literal
 * `delegated_user`: the Auth.md vocabulary is a closed set (identity_assertion,
 * verified_email, anonymous), and a value outside it makes a scanner report
 * "agent_auth metadata was not found" even though the block is present and
 * otherwise complete. The semantics match — the token asserts the identity of
 * the admin who authorised it.
 */
final class OAuthAuthMethodDescriptor implements AuthMethodDescriptorInterface
{
    public function getAuthMethodDescriptor(AgentContext $context): AuthMethodDescriptor
    {
        return new AuthMethodDescriptor(
            id: 'oauth2',
            title: 'OAuth 2.1 with dynamic client registration',
            documentation: $this->documentation($context),
            registerUri: $context->url('/mcp/oauth/register'),
            skillUri: $context->url('/.well-known/oauth-authorization-server'),
            registrationMethods: ['oauth_dynamic_client_registration'],
            identityTypes: ['identity_assertion'],
            credentialTypes: ['oauth2_access_token'],
            revocationUri: $context->url('/mcp/oauth/revoke'),
        );
    }

    private function documentation(AgentContext $context): string
    {
        return <<<MARKDOWN
            Access is **delegated, never autonomous**: a token always represents a
            human administrator of this shop, and an agent can only reach what that
            administrator may reach. If nobody authorises the agent, no token is issued.

            ### Register

            Register as an OAuth client with RFC 7591 dynamic client registration:

                POST {$context->url('/mcp/oauth/register')}
                Content-Type: application/json

                {
                  "client_name": "Your agent",
                  "redirect_uris": ["http://127.0.0.1:<port>/callback"]
                }

            Registration is open, but redirect URIs are restricted to loopback
            addresses (RFC 8252) and to HTTPS URIs the operator has allow-listed.
            Anything else is rejected with `invalid_redirect_uri` — ask the operator
            to allow-list it rather than retrying.

            ### Authorise

            Run the authorization code flow. PKCE with `S256` is mandatory; a request
            without a code challenge is rejected.

                GET  {$context->url('/admin/mcp/authorize')}
                     ?response_type=code&client_id=...&redirect_uri=...
                     &code_challenge=...&code_challenge_method=S256
                POST {$context->url('/mcp/oauth/token')}

            An administrator signs in and consents during the authorize step. Public
            clients may use `token_endpoint_auth_method=none`; PKCE carries the
            security guarantee.

            ### Use the credential

            Send the bearer token in the header — the only accepted position; tokens
            in query strings are refused:

                Authorization: Bearer <access_token>

            ### Revoke

                POST {$context->url('/mcp/oauth/revoke')}
            MARKDOWN;
    }
}
