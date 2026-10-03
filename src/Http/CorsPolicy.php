<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Http;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * CORS for the token, registration and revocation endpoints: an allow-list of
 * origins instead of `*`.
 *
 * `*` without credentials looked harmless, and for the discovery documents it
 * is (they stay public). For the endpoints that mint and revoke credentials
 * it let any page a user visits drive the token exchange from the user's
 * browser. Browser-based MCP clients are listed in
 * `koh_mcp_oauth.cors_allowed_origins`; server-side clients send no Origin and
 * need no CORS at all.
 */
final class CorsPolicy
{
    /** @param list<string> $allowedOrigins exact origins */
    public function __construct(
        private readonly array $allowedOrigins = [],
    ) {
    }

    public function apply(Request $request, Response $response): Response
    {
        $origin = $request->headers->get('Origin');
        if (null !== $origin && \in_array($origin, $this->allowedOrigins, true)) {
            $response->headers->set('Access-Control-Allow-Origin', $origin);
            $response->headers->set('Vary', 'Origin');
        }

        return $response;
    }
}
