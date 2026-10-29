<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Http;

use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

/**
 * Builds the {@see EndpointRateLimiter} from `koh_mcp_oauth.rate_limits`:
 * sliding windows per client address (register, token) or per credential
 * (mcp), stored in the given cache pool.
 */
final class EndpointRateLimiterFactory
{
    /** @param array<string, array{limit?: int, interval?: string}> $limits */
    public static function create(array $limits, CacheItemPoolInterface $cache): EndpointRateLimiter
    {
        $storage = new CacheStorage($cache);
        $limiters = [];
        foreach ($limits as $endpoint => $limit) {
            if (($limit['limit'] ?? 0) < 1) {
                continue;
            }
            $limiters[$endpoint] = new RateLimiterFactory([
                'id' => 'koh_mcp_oauth_'.$endpoint,
                'policy' => 'sliding_window',
                'limit' => $limit['limit'],
                'interval' => $limit['interval'] ?? '1 hour',
            ], $storage);
        }

        return new EndpointRateLimiter($limiters);
    }
}
