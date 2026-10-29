<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Http;

use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
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

    /**
     * AUD-068-F01: /auth.md promises a limit per credential. One credential
     * runs out; another, used from the same address, is untouched.
     */
    public function testTheMcpLimitIsPerCredential(): void
    {
        $limiter = EndpointRateLimiterFactory::create(['mcp' => ['limit' => 2, 'interval' => '1 minute']], new ArrayAdapter());
        $first = EndpointRateLimiter::credentialKey($this->token(id: 1));
        $second = EndpointRateLimiter::credentialKey($this->token(id: 2));

        self::assertNull($limiter->checkCredential($first));
        self::assertNull($limiter->checkCredential($first));
        $refused = $limiter->checkCredential($first);

        self::assertSame(429, $refused?->getStatusCode());
        self::assertGreaterThan(0, (int) $refused->headers->get('Retry-After'));
        self::assertLessThanOrEqual(61, (int) $refused->headers->get('Retry-After'), 'within the window, plus a second of rounding');
        self::assertStringContainsString('no-store', (string) $refused->headers->get('Cache-Control'));
        self::assertStringContainsString('too_many_requests', (string) $refused->getContent());
        self::assertNull($limiter->checkCredential($second), 'another credential has its own budget');
    }

    /** Refreshing yields a new access token; it must not yield a new budget. */
    public function testAccessTokensOfOneAuthorisationShareTheirLimit(): void
    {
        $limiter = EndpointRateLimiterFactory::create(['mcp' => ['limit' => 1, 'interval' => '1 minute']], new ArrayAdapter());
        $family = str_repeat('f', 32);

        self::assertNull($limiter->checkCredential(EndpointRateLimiter::credentialKey($this->token(id: 1, family: $family))));
        self::assertSame(
            429,
            $limiter->checkCredential(EndpointRateLimiter::credentialKey($this->token(id: 2, family: $family)))?->getStatusCode(),
        );
    }

    public function testTheMcpLimitIsOnlyEnforcedWhenConfigured(): void
    {
        $limiter = EndpointRateLimiterFactory::create(['mcp' => ['limit' => 0, 'interval' => '1 minute']], new ArrayAdapter());

        for ($i = 0; $i < 50; ++$i) {
            self::assertNull($limiter->checkCredential('token:1'));
        }
    }

    /**
     * The key lands in a cache key. It may name the token or its authorisation,
     * never carry the bearer value.
     */
    public function testTheCredentialKeyNeverCarriesTheBearerValue(): void
    {
        $raw = 'tbmcp_'.str_repeat('a', 64);
        $hash = hash('sha256', $raw);

        $grant = EndpointRateLimiter::credentialKey(new McpAccessToken($hash, 7, 'agent', refreshFamily: str_repeat('f', 32)));
        $cli = EndpointRateLimiter::credentialKey($this->token(id: 42, hash: $hash));
        $unsaved = EndpointRateLimiter::credentialKey(new McpAccessToken($hash, 7, 'agent'));

        self::assertSame('grant:'.str_repeat('f', 32), $grant);
        self::assertSame('token:42', $cli);
        self::assertSame('hash:'.$hash, $unsaved, 'the stored hash, not the token');
        foreach ([$grant, $cli, $unsaved] as $key) {
            self::assertStringNotContainsString($raw, $key);
            self::assertStringNotContainsString('tbmcp_', $key);
        }
    }

    private function token(int $id, ?string $family = null, ?string $hash = null): McpAccessToken
    {
        $token = new McpAccessToken($hash ?? hash('sha256', 'tbmcp_'.$id), 7, 'agent', refreshFamily: $family);
        (new \ReflectionProperty(McpAccessToken::class, 'id'))->setValue($token, $id);

        return $token;
    }

    private function from(string $ip): Request
    {
        return Request::create('https://shop.example/mcp/oauth/register', 'POST', server: ['REMOTE_ADDR' => $ip]);
    }
}
