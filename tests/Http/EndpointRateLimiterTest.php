<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Http;

use Koh\SyliusMcpOAuth\Http\EndpointRateLimiterFactory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;

final class EndpointRateLimiterTest extends TestCase
{
    /** Open registration, but not unlimited: the third call from one address within the window is refused. */
    public function testRegistrationIsLimitedPerAddress(): void
    {
        $limiter = EndpointRateLimiterFactory::create(['register' => ['limit' => 2, 'interval' => '1 hour']], new ArrayAdapter());

        self::assertNull($limiter->check('register', $this->from('198.51.100.1')));
        self::assertNull($limiter->check('register', $this->from('198.51.100.1')));
        $refused = $limiter->check('register', $this->from('198.51.100.1'));

        self::assertSame(429, $refused?->getStatusCode());
        self::assertGreaterThan(0, (int) $refused->headers->get('Retry-After'));
        self::assertNull($limiter->check('register', $this->from('198.51.100.2')), 'another address has its own budget');
    }

    public function testALimitOfZeroSwitchesItOff(): void
    {
        $limiter = EndpointRateLimiterFactory::create(['token' => ['limit' => 0, 'interval' => '1 minute']], new ArrayAdapter());

        for ($i = 0; $i < 50; ++$i) {
            self::assertNull($limiter->check('token', $this->from('198.51.100.1')));
        }
    }

    private function from(string $ip): Request
    {
        return Request::create('https://shop.example/mcp/oauth/register', 'POST', server: ['REMOTE_ADDR' => $ip]);
    }
}
