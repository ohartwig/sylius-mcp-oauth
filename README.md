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

### `access_token_ttl`

Lifetime in seconds of tokens issued through the OAuth flow (default `3600`,
minimum `60`). `expires_in` in the token response carries the same value. No
refresh token is issued: when the token expires, the client runs the
authorization flow again and the administrator approves it again on the
consent screen. Raise the value if hourly
re-consent is too frequent for your agents — that is a trade-off you make
explicitly, not a default.

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
