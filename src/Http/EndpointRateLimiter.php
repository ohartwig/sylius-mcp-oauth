<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Http;

use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * The bundle's rate limits: per address on the two OAuth endpoints anyone can
 * call, per credential on the MCP endpoint.
 *
 * Registration is open by design — a client cannot authenticate before it
 * exists — so without a limit one script fills the client table. The token
 * endpoint guards PKCE verifiers and refresh tokens; a limit there turns
 * guessing from cheap to slow. The authorize endpoint needs none: it sits
 * behind the admin login. Those two are keyed by client address. Behind a
 * proxy that is only meaningful with framework.trusted_proxies set;
 * otherwise every request shares the proxy's address and one limit — which
 * fails closed, not open.
 *
 * The MCP endpoint is where a token acts as an administrator, so its limit is
 * keyed on the credential, not the address: a stolen token is throttled
 * wherever it is used from, and many agents behind one egress address (a
 * hosted connector) do not share a budget. See {@see self::credentialKey()}.
 */
final class EndpointRateLimiter
{
    /** Limiter name of the per-credential limit on the MCP endpoint. */
    public const MCP = 'mcp';

    /** @param array<string, RateLimiterFactoryInterface> $limiters keyed by endpoint: register, token, mcp */
    public function __construct(
        private readonly array $limiters = [],
    ) {
    }

    /** null when the request may proceed; otherwise the 429 to send. */
    public function check(string $endpoint, Request $request): ?Response
    {
        return $this->consume($endpoint, $request->getClientIp() ?? 'unknown', 'Too many requests from this address. Retry later.');
    }

    /**
     * null when the request may proceed; otherwise the 429 to send.
     *
     * @param string $credentialKey from {@see self::credentialKey()}
     */
    public function checkCredential(string $credentialKey): ?Response
    {
        return $this->consume(self::MCP, $credentialKey, 'Too many requests with this credential. Retry later.');
    }

    /**
     * What the MCP limit counts against. Never the bearer value: the limiter
     * key ends up in a cache key, and a credential has no business there.
     *
     * - `grant:<family>` for tokens from the OAuth flow. Every access token
     *   issued from one consent shares the refresh family, so refreshing —
     *   which a holder of the refresh token can do at will — does not buy a
     *   fresh budget. The family is a random identifier, not a secret: it is
     *   stored in clear and spends nothing on its own.
     * - `token:<id>` for tokens without a family (CLI tokens, tokens issued
     *   before refresh tokens existed).
     * - `hash:<sha256>` only for an entity without an id, which a token that
     *   has been looked up never is. The stored hash, not the raw token.
     */
    public static function credentialKey(McpAccessToken $token): string
    {
        $family = $token->getRefreshFamily();
        if (null !== $family && '' !== $family) {
            return 'grant:'.$family;
        }

        $id = $token->getId();
        if (null !== $id) {
            return 'token:'.$id;
        }

        return 'hash:'.$token->getTokenHash();
    }

    private function consume(string $endpoint, string $key, string $message): ?Response
    {
        $factory = $this->limiters[$endpoint] ?? null;
        if (null === $factory) {
            return null;
        }

        $limit = $factory->create($key)->consume();
        if ($limit->isAccepted()) {
            return null;
        }

        $retryAfter = max(1, $limit->getRetryAfter()->getTimestamp() - time());

        return new JsonResponse(
            ['error' => 'too_many_requests', 'error_description' => $message],
            Response::HTTP_TOO_MANY_REQUESTS,
            ['Retry-After' => (string) $retryAfter, 'Cache-Control' => 'no-store'],
        );
    }
}
