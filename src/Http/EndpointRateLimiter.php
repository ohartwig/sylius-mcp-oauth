<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Http;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * Per-address limits on the two OAuth endpoints anyone can call.
 *
 * Registration is open by design — a client cannot authenticate before it
 * exists — so without a limit one script fills the client table. The token
 * endpoint guards PKCE verifiers and refresh tokens; a limit there turns
 * guessing from cheap to slow. The authorize endpoint needs none: it sits
 * behind the admin login.
 *
 * Keyed by client address. Behind a proxy that is only meaningful with
 * framework.trusted_proxies set; otherwise every request shares the proxy's
 * address and one limit — which fails closed, not open.
 */
final class EndpointRateLimiter
{
    /** @param array<string, RateLimiterFactoryInterface> $limiters keyed by endpoint: register, token */
    public function __construct(
        private readonly array $limiters = [],
    ) {
    }

    /** null when the request may proceed; otherwise the 429 to send. */
    public function check(string $endpoint, Request $request): ?Response
    {
        $factory = $this->limiters[$endpoint] ?? null;
        if (null === $factory) {
            return null;
        }

        $limit = $factory->create($request->getClientIp() ?? 'unknown')->consume();
        if ($limit->isAccepted()) {
            return null;
        }

        $retryAfter = max(1, $limit->getRetryAfter()->getTimestamp() - time());

        return new JsonResponse(
            ['error' => 'too_many_requests', 'error_description' => 'Too many requests from this address. Retry later.'],
            Response::HTTP_TOO_MANY_REQUESTS,
            ['Retry-After' => (string) $retryAfter, 'Cache-Control' => 'no-store'],
        );
    }
}
