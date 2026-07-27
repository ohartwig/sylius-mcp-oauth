<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
SPDX-License-Identifier: MIT
-->

# koh/sylius-mcp-oauth

OAuth 2.1 authorization server for MCP clients on Sylius: dynamic client
registration, mandatory PKCE, and the discovery metadata an agent needs to find
its way in.

Access is **delegated, never autonomous**. A token always represents a human
administrator, and an agent reaches exactly what that administrator may reach.
If nobody authorises the agent, no token exists.

## Install

```bash
composer require koh/sylius-mcp-oauth
```

```php
// config/bundles.php
Koh\SyliusMcpOAuth\KohSyliusMcpOAuthBundle::class => ['all' => true],
```

```yaml
# config/routes/koh_agent.yaml
koh_mcp_oauth:
    resource: '@KohSyliusMcpOAuthBundle/config/routes.php'
```

```yaml
# config/packages/security.yaml
security:
    firewalls:
        mcp:
            pattern: ^/_mcp
            stateless: true
            provider: sylius_admin_user_provider
            custom_authenticators:
                - Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator
            entry_point: Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator
```

The entity mapping registers itself — no `doctrine.yaml` edit needed.

## Endpoints

| Path | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata, incl. `agent_auth` |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `/mcp/oauth/register` | RFC 7591 dynamic client registration |
| `/mcp/oauth/token` | token exchange |
| `/mcp/oauth/revoke` | revocation |
| `/admin/mcp/authorize` | consent — deliberately under `/admin` |

`/authorize` sits under `/admin` so the admin firewall covers it: consent
requires a signed-in administrator. Everything else is public, because a client
cannot authenticate before it has registered.

## Configure

```yaml
# config/packages/koh_mcp_oauth.yaml
koh_mcp_oauth:
    resource_path: '/_mcp'
    access_token_ttl: 3600
    allowed_redirect_uris: []   # HTTPS URIs, in addition to loopback
```

Redirect URIs are restricted to loopback addresses (RFC 8252, for native and
local agents) plus whatever the operator allow-lists. Anything else is rejected
with `invalid_redirect_uri`.

## Three details worth knowing

### URLs come from the channel, not the request

TLS usually terminates at an ingress, and without `framework.trusted_proxies`
the request reports the internal host. In an issuer that is not cosmetic: a
client that compares the issuer against the one it discovered will reject the
token. The metadata is built from `AgentContext` instead — see
`koh/sylius-agent-contracts`.

### `identity_types_supported` says `identity_assertion`

`delegated_user` is the more literal description, but the Auth.md vocabulary is
a closed set (`identity_assertion`, `verified_email`, `anonymous`). A value
outside it makes scanners report *agent_auth metadata was not found* even though
the block is present and complete. The semantics match anyway — the token
asserts the identity of the administrator who authorised it.

### The `agent_auth` block is aggregated, not hard-coded

It is built from every registered `AuthMethodDescriptorInterface`, so a shop that
also installs `koh/sylius-web-bot-auth` advertises both credential types without
either bundle knowing the other exists. The same descriptor feeds `/auth.md`, so
the prose and the machine-readable metadata cannot drift apart.

## Issuing a token by hand

```bash
bin/console koh:mcp:token:create admin@example.com
```

The raw token is shown once and never stored.

## Upgrading from an in-application implementation

If these classes previously lived in your `App\` namespace:

1. **Delete the originals.** Leaving `App\Entity\Mcp\McpAccessToken` in place
   maps two classes onto one table and the container fails to warm up. Doctrine
   has no way to exclude a subdirectory from an existing mapping.
2. Point `security.yaml` at `Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator`.
3. Replace the route definitions with the bundle's `config/routes.php`. **Route
   names are unchanged**, so redirect URIs already issued to registered clients
   keep resolving.
4. Run `bin/console doctrine:schema:validate --skip-sync`. It must report the
   schema in sync — that is the proof no migration is required. The entities
   keep their explicit table names (`app_mcp_access_token`,
   `app_mcp_authorization_code`, `app_mcp_oauth_client`), so live tokens survive
   the move.

## Decommission

Revoke outstanding tokens first (`/mcp/oauth/revoke`, or truncate
`app_mcp_access_token`) — removing the bundle stops them being *checked*, not
being valid elsewhere. Then drop the `composer require`, the bundle entry, the
route import, the firewall and the three tables.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Advisories
are published as CSAF 2.0 at <https://ole-hartwig.eu/.well-known/csaf/>.

## Licence

MIT — see [LICENSE](LICENSE).
