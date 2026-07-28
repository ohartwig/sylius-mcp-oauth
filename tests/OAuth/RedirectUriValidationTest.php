<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Client registration is open by design — public clients, no secret — so the
 * redirect_uri allow-list is the only thing standing between an anonymous
 * registration and a Location header the server will emit.
 */
final class RedirectUriValidationTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function rejected(): iterable
    {
        // filter_var(..., FILTER_VALIDATE_URL) accepts every one of these.
        yield 'javascript scheme' => ['javascript://comment%0aalert(1)'];
        yield 'file scheme' => ['file:///etc/passwd'];
        yield 'ftp scheme' => ['ftp://example.com/cb'];
        yield 'plain http off-loopback' => ['http://attacker.example/cb'];
        yield 'fragment' => ['https://client.example/cb#tokens'];
        yield 'no host' => ['https:///cb'];
        yield 'no scheme' => ['//client.example/cb'];
    }

    /** @return iterable<string, array{string}> */
    public static function accepted(): iterable
    {
        yield 'https' => ['https://client.example/cb'];
        yield 'https with query' => ['https://client.example/cb?x=1'];
        yield 'loopback v4' => ['http://127.0.0.1:52100/cb'];
        yield 'loopback v6' => ['http://[::1]:52100/cb'];
        yield 'localhost' => ['http://localhost:52100/cb'];
        yield 'private-use scheme' => ['com.example.mcpclient:/oauth/cb'];
    }

    #[DataProvider('rejected')]
    public function testUnusableRedirectUriIsRefused(string $uri): void
    {
        $this->expectException(OAuthException::class);

        $this->server()->registerClient('Some Client', [$uri]);
    }

    #[DataProvider('accepted')]
    public function testUsableRedirectUriIsAccepted(string $uri): void
    {
        $client = $this->server()->registerClient('Some Client', [$uri]);

        self::assertSame([$uri], $client->getRedirectUris());
    }

    /**
     * One bad entry poisons the whole registration: a client that keeps a valid
     * URI alongside a rejected one would still be able to use the rejected one.
     */
    public function testOneUnusableUriRejectsTheWholeRegistration(): void
    {
        $this->expectException(OAuthException::class);

        $this->server()->registerClient('Some Client', [
            'https://client.example/cb',
            'javascript://comment%0aalert(1)',
        ]);
    }

    private function server(): OAuthServer
    {
        $em = $this->createMock(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($this->createMock(EntityRepository::class));

        return new OAuthServer($em);
    }
}
