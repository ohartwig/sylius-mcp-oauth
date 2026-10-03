<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * The protected resource of this server — the MCP endpoint URL — for RFC 8707
 * audience binding.
 *
 * A token is bound to the resource it was requested for, and accepted only
 * there. The MCP authorization specification asks for exactly this: a token
 * issued for one MCP server must not be usable at another, or a malicious
 * server the user also connected could replay the tokens it was given.
 *
 * The canonical URL comes from the AgentContext, the same source as the RFC
 * 9728 metadata's `resource`, so what a client discovers and what it is
 * checked against cannot drift apart. Comparison ignores a trailing slash and
 * the case of scheme and host (RFC 3986 §6.2.2.1), nothing else.
 */
final class ResourceIndicator
{
    public function __construct(
        private readonly ?AgentContextFactoryInterface $contextFactory = null,
        private readonly string $resourcePath = '/_mcp',
    ) {
    }

    public function canonical(?Request $request = null): ?string
    {
        if (null !== $this->contextFactory) {
            try {
                return $this->contextFactory->create()->url($this->resourcePath);
            } catch (\Throwable) {
                // No channel resolvable (CLI, misconfigured host): fall back
                // to the request, if there is one.
            }
        }

        return null !== $request ? $request->getSchemeAndHttpHost().$this->resourcePath : null;
    }

    public function matches(string $candidate, ?Request $request = null): bool
    {
        $canonical = $this->canonical($request);

        return null !== $canonical && self::normalise($candidate) === self::normalise($canonical);
    }

    private static function normalise(string $uri): string
    {
        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme'], $parts['host'])) {
            return $uri;
        }

        return strtolower($parts['scheme']).'://'.strtolower($parts['host'])
            .(isset($parts['port']) ? ':'.$parts['port'] : '')
            .rtrim($parts['path'] ?? '', '/')
            .(isset($parts['query']) ? '?'.$parts['query'] : '');
    }
}
