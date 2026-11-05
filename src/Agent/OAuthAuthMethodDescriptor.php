<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Model\AuthMethodDescriptor;
use Koh\SyliusAgentContracts\Provider\AuthMethodDescriptorInterface;
use Koh\SyliusMcpOAuth\Controller\AgentIdentityController;

/**
 * Describes the OAuth path once, for both /auth.md and the agent_auth block.
 *
 * The `agent_auth` block follows auth.md v0.6.0 (github.com/workos/auth.md,
 * AUTH.md Step 1b). It declares only what this bundle serves: `anonymous` and
 * `service_auth` registration at the identity endpoint, the claim endpoint,
 * and `skill` pointing at /auth.md. It does not declare `identity_assertion`
 * — that type means accepting ID-JAGs from trusted identity providers, which
 * this server does not — and no `events_endpoint`, which only matters for
 * ID-JAG providers. With `koh_mcp_oauth.agent_registration.enabled` off,
 * nothing but `skill` is declared.
 *
 * The rate limits are printed from `koh_mcp_oauth.rate_limits`, the same
 * values the limiter enforces, so the document cannot promise a limit the
 * shop does not have (AUD-068-F01): a limit set to 0 is not mentioned.
 */
final class OAuthAuthMethodDescriptor implements AuthMethodDescriptorInterface
{
    /**
     * @param array<string, array{limit?: int, interval?: string}> $rateLimits      `koh_mcp_oauth.rate_limits`
     * @param list<string>                                          $postClaimScopes what claiming grants
     */
    public function __construct(
        private readonly array $rateLimits = [],
        private readonly string $resourcePath = '/_mcp',
        private readonly bool $agentRegistration = false,
        private readonly array $postClaimScopes = ['mcp'],
        private readonly int $claimTtl = 3600,
    ) {
    }

    public function getAuthMethodDescriptor(AgentContext $context): AuthMethodDescriptor
    {
        return new AuthMethodDescriptor(
            id: 'oauth2',
            title: 'OAuth 2.1 and agent registration',
            documentation: $this->documentation($context),
            skillUri: $context->url('/auth.md'),
            identityTypes: $this->agentRegistration ? ['anonymous', 'service_auth'] : [],
            identityEndpoint: $this->agentRegistration ? $context->url(AgentIdentityController::IDENTITY_PATH) : null,
            claimEndpoint: $this->agentRegistration ? $context->url(AgentIdentityController::CLAIM_PATH) : null,
        );
    }

    private function documentation(AgentContext $context): string
    {
        $intro = <<<MARKDOWN
            Access is **delegated, never autonomous**: a token always represents a
            human administrator of this shop, and an agent can only reach what that
            administrator may reach. If nobody authorises the agent, no token is issued.

            Discovery: `{$context->url('/.well-known/oauth-protected-resource')}` names
            the resource (`{$context->url($this->resourcePath)}`), and
            `{$context->url('/.well-known/oauth-authorization-server')}` carries the
            endpoints and the `agent_auth` block.
            MARKDOWN;

        return $intro
            .($this->agentRegistration ? "\n\n".$this->agentRegistrationSection($context) : '')
            ."\n\n".$this->oauthSection($context)
            .$this->rateLimitSection($context);
    }

    private function agentRegistrationSection(AgentContext $context): string
    {
        $identity = $context->url(AgentIdentityController::IDENTITY_PATH);
        $claim = $context->url(AgentIdentityController::CLAIM_PATH);
        $token = $context->url('/mcp/oauth/token');
        $scopes = implode(' ', $this->postClaimScopes);
        $window = intdiv($this->claimTtl, 60);

        return <<<MARKDOWN
            ### Agent registration (auth.md)

            Supported registration types: `anonymous` and `service_auth`. There is
            no `identity_assertion` (no identity provider is trusted), and
            `pre_claim_scopes` is empty: an identity grants nothing until an
            administrator of this shop claims it.

            Register:

                POST {$identity}
                Content-Type: application/json

                {"type": "anonymous"}

            or, naming the administrator by email:

                {"type": "service_auth", "login_hint": "admin@example.com"}

            Keep `claim_token` in memory; it is returned once. For `anonymous`, start
            the claim ceremony (`email` optional, binds it to that administrator):

                POST {$claim}
                Content-Type: application/json

                {"claim_token": "clm_...", "email": "admin@example.com"}

            Show the administrator `verification_uri` and the six-digit `user_code`.
            They sign in to the shop admin and type the code there; it is valid for
            ten minutes, five wrong entries end the attempt. The whole claim window
            is {$window} minutes. Meanwhile poll, honouring `interval`:

                POST {$token}
                Content-Type: application/x-www-form-urlencoded

                grant_type=urn:workos:agent-auth:grant-type:claim&claim_token=clm_...

            Until the claim, the answer is `authorization_pending`; polling faster
            than `interval` gives `slow_down`; `expired_token` means start a new
            attempt (or register again once the window has closed). On success you
            receive, once, an access token with the scope `{$scopes}`, acting as the
            administrator who claimed, plus an `identity_assertion`. Exchange that
            assertion for further access tokens until `assertion_expires`:

                POST {$token}
                Content-Type: application/x-www-form-urlencoded

                grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<identity_assertion>

            `invalid_grant` there means the registration was revoked by the
            administrator or the assertion expired: register again. The
            `events_endpoint` of the profile is not offered.
            MARKDOWN;
    }

    private function oauthSection(AgentContext $context): string
    {
        return <<<MARKDOWN
            ### OAuth clients (MCP)

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

            RFC 7009, form-encoded `token=<access_token>`:

                POST {$context->url('/mcp/oauth/revoke')}
            MARKDOWN;
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
        if ($this->agentRegistration && null !== $identity = $this->limit('identity')) {
            $lines[] = \sprintf('- Agent registration and claim: %s per client address.', $identity);
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
