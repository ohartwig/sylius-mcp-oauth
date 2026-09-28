<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

/**
 * Decides which redirect URIs a client may register and be sent to.
 *
 * Two independent checks, both required:
 *
 * 1. **Well-formed** ({@see assertWellFormed()}): https with a host, http on a
 *    loopback host, or a private-use scheme; never a fragment. This is the
 *    syntactic floor and applies to the configuration as well.
 * 2. **Allow-listed** ({@see isAllowed()}): the URI is on the operator's
 *    `allowed_redirect_uris` list. Comparison is an exact string match
 *    (OAuth 2.1 §2.3.1, RFC 3986 §6.2.1 simple string comparison) — no
 *    prefix, no wildcard, no case folding. The one exception is RFC 8252 §7.3:
 *    for an `http` URI on a loopback host the port is ignored, because a
 *    native client picks an ephemeral port at request time.
 *
 * An empty list allows nothing. Registration is open by design (public
 * clients, no secret), so an allow-list that defaulted to "anything
 * well-formed" would let anyone register an attacker-controlled HTTPS
 * redirect and phish an administrator's consent (THR-AGENT-014).
 */
final class RedirectUriPolicy
{
    /**
     * Hosts on which plain http is acceptable (RFC 8252 §7.3). `localhost` is
     * accepted syntactically because widely used MCP clients register it,
     * although RFC 8252 §8.3 recommends the IP literal; the allow-list decides.
     */
    private const LOOPBACK_HOSTS = ['127.0.0.1', '::1', '[::1]', 'localhost'];

    /** @var list<string> */
    private readonly array $allowed;

    /**
     * @param list<string> $allowed exact redirect URIs; loopback entries match any port
     */
    public function __construct(array $allowed = [])
    {
        $this->allowed = array_values(array_filter($allowed, static fn (string $uri): bool => '' !== $uri));
    }

    /**
     * Throws unless the URI is both well-formed and allow-listed.
     *
     * @throws OAuthException invalid_redirect_uri (RFC 7591 §3.2.2)
     */
    public function assertRegistrable(string $uri): void
    {
        self::assertWellFormed($uri);

        if (!$this->isAllowed($uri)) {
            throw new OAuthException(
                'invalid_redirect_uri',
                'redirect_uri is not on the allow-list of this authorization server.',
            );
        }
    }

    /**
     * Exact match against the allow-list, ignoring only the port of a loopback
     * http URI. Does not re-check well-formedness: a URI can only be on the
     * list if the configuration accepted it.
     */
    public function isAllowed(string $uri): bool
    {
        if (\in_array($uri, $this->allowed, true)) {
            return true;
        }

        $portless = self::withoutLoopbackPort($uri);
        if (null === $portless) {
            return false;
        }

        foreach ($this->allowed as $entry) {
            if (self::withoutLoopbackPort($entry) === $portless) {
                return true;
            }
        }

        return false;
    }

    /**
     * OAuth 2.1 §2.3.1 / RFC 8252 §7: a redirect URI is https, http on the
     * loopback interface, or a private-use scheme.
     *
     * FILTER_VALIDATE_URL is not a substitute. It accepts `javascript://x%0a…`,
     * `file:///etc/passwd` and `ftp://…`.
     *
     * A fragment is rejected outright: RFC 6749 §3.1.2 forbids it, and the
     * authorization response appends its own query, which a fragment would
     * swallow.
     *
     * @throws OAuthException invalid_redirect_uri
     */
    public static function assertWellFormed(string $uri): void
    {
        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme'])) {
            throw new OAuthException('invalid_redirect_uri', 'redirect_uri is not a valid URL.');
        }
        if (isset($parts['fragment'])) {
            throw new OAuthException('invalid_redirect_uri', 'redirect_uri must not contain a fragment.');
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host'] ?? '');

        if ('https' === $scheme) {
            if ('' === $host) {
                throw new OAuthException('invalid_redirect_uri', 'redirect_uri must name a host.');
            }

            return;
        }

        if ('http' === $scheme) {
            // RFC 8252 §7.3: loopback only, and only for native clients.
            if (\in_array($host, self::LOOPBACK_HOSTS, true)) {
                return;
            }

            throw new OAuthException(
                'invalid_redirect_uri',
                'Plain http is only allowed on the loopback interface; use https.',
            );
        }

        // RFC 8252 §7.1: a private-use scheme is a reverse-domain name, so it
        // always contains a dot. That excludes javascript:, data:, file: and ftp:
        // without needing to enumerate them.
        if (str_contains($scheme, '.')) {
            return;
        }

        throw new OAuthException(
            'invalid_redirect_uri',
            \sprintf('Scheme "%s" is not allowed for a redirect_uri.', $scheme),
        );
    }

    /**
     * `http://127.0.0.1:52100/cb` → `http://127.0.0.1/cb`; null for anything
     * that is not a loopback http URI. Scheme and host are compared verbatim,
     * so `127.0.0.1` never matches `localhost` or `[::1]`.
     */
    private static function withoutLoopbackPort(string $uri): ?string
    {
        if (1 !== preg_match('#^http://(127\.0\.0\.1|\[::1\]|localhost)(?::\d{1,5})?([/?].*)?$#s', $uri, $m)) {
            return null;
        }

        return 'http://'.$m[1].($m[2] ?? '');
    }
}
