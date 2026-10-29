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
 *
 * The rate limits are printed from `koh_mcp_oauth.rate_limits`, the same
 * values the limiter enforces, so the document cannot promise a limit the
 * shop does not have (AUD-068-F01): a limit set to 0 is not mentioned.
 */
final class OAuthAuthMethodDescriptor implements AuthMethodDescriptorInterface
{
    /** @param array<string, array{limit?: int, interval?: string}> $rateLimits `koh_mcp_oauth.rate_limits` */
    public function __construct(
        private readonly array $rateLimits = [],
        private readonly string $resourcePath = '/_mcp',
    ) {
    }

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
            MARKDOWN.$this->rateLimitSection($context);
    }

    private function rateLimitSection(AgentContext $context): string
    {
        $lines = [];
        if (null !== $mcp = $this->limit('mcp')) {
            $lines[] = \sprintf(
                '- `%s`: %s per credential. Every access token from one authorisation counts against the same limit; refreshing does not reset it.',
                $context->url($this->resourcePath),
                $mcp,
            );
        }
        if (null !== $token = $this->limit('token')) {
            $lines[] = \sprintf('- Token endpoint: %s per client address.', $token);
        }
        if (null !== $register = $this->limit('register')) {
            $lines[] = \sprintf('- Registration: %s per client address.', $register);
        }
        if ([] === $lines) {
            return '';
        }

        return "\n\n### Rate limits\n\n"
            .implode("\n", $lines)
            ."\n\nOver a limit the answer is `429` with `Retry-After`; wait that long before retrying.";
    }

    private function limit(string $endpoint): ?string
    {
        $limit = $this->rateLimits[$endpoint]['limit'] ?? 0;
        if ($limit < 1) {
            return null;
        }

        // Same interval fallback as EndpointRateLimiterFactory.
        return \sprintf('%d requests per %s', $limit, $this->rateLimits[$endpoint]['interval'] ?? '1 hour');
    }
}
