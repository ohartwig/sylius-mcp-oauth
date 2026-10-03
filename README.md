<!--
SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
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
        # …the admin and shop firewalls follow; /mcp/oauth/ must not be
        # caught by a stateful one.

    access_control:
        # Without this rule a request with no Authorization header passes the
        # mcp firewall anonymously: the authenticator only runs when a Bearer
        # token is present. The rule is what turns "no token" into a 401.
        - { path: ^/_mcp, role: ROLE_ADMINISTRATION_ACCESS }
        # Discovery, registration, token and revocation are public by design.
        - { path: ^/mcp/oauth/, role: PUBLIC_ACCESS }
```

**The `access_control` rule for `^/_mcp` is not optional.** The firewall
alone does not refuse a request without a token.

The entity mapping and, from 3.0, the bundle's migrations register themselves
— no `doctrine.yaml` or `doctrine_migrations.yaml` edit needed. Run
`bin/console doctrine:migrations:migrate` after upgrading.

## Endpoints

| Path | Purpose |
|---|---|
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata, incl. `agent_auth` |
| `/.well-known/oauth-protected-resource` | RFC 9728 metadata |
| `/mcp/oauth/register` | RFC 7591 dynamic client registration |
| `/mcp/oauth/token` | token exchange |
| `/mcp/oauth/revoke` | revocation |
| `/admin/mcp/authorize` | consent — deliberately under `/admin` |
| `/admin/mcp/access-tokens` | token overview and revocation in the Sylius admin |

`/authorize` sits under `/admin` so the admin firewall covers it: consent
requires a signed-in administrator. Everything else is public, because a client
cannot authenticate before it has registered.

## Configure

```yaml
# config/packages/koh_mcp_oauth.yaml
koh_mcp_oauth:
    resource_path: '/_mcp'
    access_token_ttl: 3600
    allowed_redirect_uris:
        - 'https://claude.ai/api/mcp/auth_callback'
        - 'http://127.0.0.1/callback'
        - 'http://localhost/callback'
```

### `allowed_redirect_uris`

The only redirect URIs a client may register and be sent to. Registration is
open (public clients, no secret), so this list is what stops anyone from
registering a client whose redirect points at their own server and phishing an
administrator's consent.

- **Exact string match** (OAuth 2.1 §2.3.1): no prefix, no wildcard, no case
  folding. `https://client.example/cb` does not admit `https://client.example/cb/`,
  `…/cb?x=1` or `https://client.example:8443/cb`.
- **Loopback** (`http://127.0.0.1`, `http://[::1]`, `http://localhost`): the
  port is ignored, because native clients pick one at request time
  (RFC 8252 §7.3). Everything else — host spelling, path, query — must match.
  `127.0.0.1` does not admit `localhost`; list each form your clients use.
  RFC 8252 §8.3 prefers the IP literal; `localhost` is accepted because common
  MCP clients register it.
- **Private-use schemes** (`com.example.app:/cb`) only when listed.
- **Empty list: nothing is allowed.** Every registration is refused with
  `invalid_redirect_uri` (RFC 7591). There is no implicit loopback or HTTPS
  default.
- The list is checked at registration **and again at `/authorize`**, so
  removing an entry stops already-registered clients from receiving codes at
  that URI. They get an on-site error page (`invalid_request`), never a
  redirect.
- Entries are validated when the container is built: plain `http` off
  loopback, fragments, and schemes such as `javascript:` fail the build.

### `access_token_ttl` and `refresh_token_ttl`

`access_token_ttl`: lifetime in seconds of access tokens (default `3600`,
minimum `60`). `expires_in` in the token response carries the same value.

`refresh_token_ttl`: lifetime of a refresh token (default `1209600`, 14
days; `0` issues none). With refresh tokens the access token can stay short
without hourly re-consent. Every refresh spends the refresh token and returns
a new pair. **A spent refresh token presented again revokes the whole
authorization** — every refresh and access token descended from it — because
one of the two parties holding it is not the client (OAuth 2.1 §4.3.1). The
client then runs the authorization flow again. A refresh may narrow the scope,
never widen it. Revoking a refresh token at `/mcp/oauth/revoke` revokes its
family.

### Scopes

| Scope | Grants |
|---|---|
| `mcp:read` | the read tools and resources |
| `mcp:write` | the write tools, and reading |
| `mcp` | both — what every token meant before 3.0 |

This server issues the scopes; koh/sylius-mcp enforces them per tool. A client
that requests none gets `default_scopes` (default `[mcp]`). The facts about a
token reach the MCP server as security-token attributes (`koh_mcp.token_id`,
`koh_mcp.client_id`, `koh_mcp.scopes`, `koh_mcp.audience`).

### Audience binding (RFC 8707)

Every authorization is bound to the MCP endpoint (`resource_path` on the
channel's URL — the `resource` of the RFC 9728 metadata). A client may send
`resource` at `/authorize` and at the token endpoint; any other value fails
with `invalid_target`. A client that sends none gets a bound token anyway.
`/_mcp` refuses a token bound to another resource. Tokens from before 3.0
and CLI tokens carry no audience and keep working.

### Rate limits and CORS

```yaml
koh_mcp_oauth:
    rate_limits:
        register: { limit: 10, interval: '1 hour' }   # per client address; 0 = off
        token: { limit: 30, interval: '1 minute' }
    cors_allowed_origins:
        - 'https://inspector.example.com'           # browser-based MCP clients only
```

Registration is open by design, so it is limited per address; the token
endpoint is limited against guessing. Over the limit: `429` with
`Retry-After`. The limits key on the client address — set
`framework.trusted_proxies` behind an ingress, or every request shares the
proxy's address and one budget.

The token, registration and revocation endpoints no longer answer
`Access-Control-Allow-Origin: *`; only listed origins get CORS headers.
Server-side clients (Claude's connectors, Claude Code) send no `Origin` and are
unaffected. The discovery documents stay public with `*`.

### Client address per token

Each access token records the address it was issued to and the address of its
last use on `/_mcp` (`created_ip`, `last_used_ip`) — for the audit trail and
the token overview, not as a binding: clients move between networks.

### Consent screen and translations

The bundle ships `@KohSyliusMcpOAuth/oauth/authorize.html.twig`. Override it
the Symfony way, at
`templates/bundles/KohSyliusMcpOAuthBundle/oauth/authorize.html.twig`. An
override must keep the `POST` to `path('mcp_oauth_authorize')`, the
`_csrf_token` field built from `csrf_token(csrf_id)`, and every entry of
`query` as a hidden field.

All user-facing text lives in the `koh_mcp_oauth` translation domain. English
and German catalogues ship with the bundle; add
`translations/koh_mcp_oauth.<locale>.yaml` in the application for other
languages or to change the wording. Without a translator, the error pages fall
back to English.

The consent and error pages are sent with `X-Frame-Options: DENY`,
`frame-ancestors 'none'` and `Cache-Control: no-store`.

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

## Token overview in the admin

`/admin/mcp/access-tokens` (sidebar: *Configuration → MCP tokens*) lists the
signed-in administrator's access tokens: client, scopes, issued (with
address), last used (with address), expiry and status. **Revoke** ends the
token at once; a token from a refresh-token family takes the family with it,
so the client cannot refresh it back. The page sits behind the admin firewall
and needs `ROLE_ADMINISTRATION_ACCESS`; revocation is a CSRF-protected POST.

```yaml
koh_mcp_oauth:
    admin:
        menu: true                                 # false: no sidebar entry (e.g. the application has its own)
        overview_role: ROLE_MCP_TOKEN_ADMIN        # sees and revokes every administrator's tokens (default: nobody)
```

An application that already has its own token page at `/admin/mcp/tokens`
keeps it; this one lives next to it.

The template is `@KohSyliusMcpOAuth/admin/tokens.html.twig`, overridable at
`templates/bundles/KohSyliusMcpOAuthBundle/admin/tokens.html.twig`. It renders
inside the base admin layout without the sidebar.

## Issuing a token by hand

```bash
bin/console mcp:token:create admin@example.com --name "CI agent"
bin/console mcp:token:create admin@example.com --ttl-days 30
bin/console mcp:token:create admin@example.com --no-expiry
```

The raw token is shown once and never stored. A CLI token expires after
**90 days** unless `--ttl-days` sets another positive number of days. A token
that never expires needs `--no-expiry`, spelled out; the two options exclude
each other.

## Upgrading to 3.0

1. **Run the migrations.** 3.0 ships its first migration
   (`Koh\SyliusMcpOAuth\Migrations\Version20261003120000`): new columns on
   `app_mcp_access_token` and `app_mcp_authorization_code`, and the table
   `app_mcp_refresh_token`. The path is registered automatically.
2. **Add the `access_control` rule for `^/_mcp`** if the application does not
   have it (see *Install*).
3. **Browser-based clients** calling the token, registration or revocation
   endpoint from another origin must be listed in `cors_allowed_origins`.
4. **Refresh tokens are on by default** (14 days). Set `refresh_token_ttl: 0`
   to keep the 2.x behaviour. With refresh tokens, consider lowering
   `access_token_ttl` again.
5. Clients now see the scopes `mcp:read` and `mcp:write` in the metadata.
   Tokens with the scope `mcp` keep full access.

## Upgrading to 2.0

2.0 enforces settings that 1.x accepted and ignored. Both changes can lock
existing clients out, so read this before deploying.

1. **List every redirect URI your clients use** in `allowed_redirect_uris`.
   With the 1.x default of `[]` every registration — loopback included — is
   refused, and clients registered under 1.x get an error page at
   `/authorize` until their URI is listed. Look up what is registered today:

   ```sql
   SELECT client_name, redirect_uris FROM app_mcp_oauth_client;
   ```

   List only the ones you recognise.
2. **Tokens now live `access_token_ttl` seconds** (default one hour) instead
   of 90 days. Set it explicitly if you want something else, e.g.
   `access_token_ttl: 86400`. Tokens issued under 1.x keep their stored
   expiry.
3. **CLI tokens expire after 90 days** unless created with `--no-expiry`.
   Tokens minted under 1.x without `--ttl-days` have no expiry in the
   database and stay valid indefinitely. Review them, and give them an end
   date or revoke them:

   ```sql
   SELECT id, name, admin_user_id, created_at FROM app_mcp_access_token
    WHERE expires_at IS NULL AND revoked = 0;
   ```
4. **The consent template is now the bundle's.** 1.x rendered
   `mcp/oauth/authorize.html.twig` from the application; 2.0 renders
   `@KohSyliusMcpOAuth/oauth/authorize.html.twig`. Move a custom template to
   `templates/bundles/KohSyliusMcpOAuthBundle/oauth/authorize.html.twig`, or
   delete it to use the bundled one.
5. `OAuthServer::TOKEN_TTL_DAYS` is gone; read the lifetime from
   `koh_mcp_oauth.access_token_ttl`.

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

The family threat model, covering this package, is at
<https://github.com/ohartwig/sylius-agent-ready/blob/main/docs/threat-model.md>.

## Licence

MIT — see [LICENSE](LICENSE).
