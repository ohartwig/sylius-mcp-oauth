<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RedirectUriPolicy;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Client registration is open by design — public clients, no secret — so the
 * redirect_uri allow-list is the only thing standing between an anonymous
 * registration and a Location header the server will emit (THR-AGENT-014).
 *
 * Two layers are exercised: well-formedness, which no allow-list entry can
 * override, and the allow-list itself, which is an exact string match except
 * for the port of a loopback http URI (RFC 8252 §7.3).
 */
#[CoversClass(RedirectUriPolicy::class)]
#[CoversClass(OAuthServer::class)]
final class RedirectUriValidationTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        // filter_var(..., FILTER_VALIDATE_URL) accepts every one of these.
        yield 'javascript scheme' => ['javascript://comment%0aalert(1)'];
        yield 'file scheme' => ['file:///etc/passwd'];
        yield 'ftp scheme' => ['ftp://example.com/cb'];
        yield 'plain http off-loopback' => ['http://attacker.example/cb'];
        yield 'loopback lookalike host' => ['http://127.0.0.1.attacker.example/cb'];
        yield 'loopback as userinfo' => ['http://127.0.0.1:52100@attacker.example/cb'];
        yield 'fragment' => ['https://client.example/cb#tokens'];
        yield 'no host' => ['https:///cb'];
        yield 'no scheme' => ['//client.example/cb'];
    }

    /** @return iterable<string, array{string}> */
    public static function wellFormed(): iterable
    {
        yield 'https' => ['https://client.example/cb'];
        yield 'https with query' => ['https://client.example/cb?x=1'];
        yield 'loopback v4' => ['http://127.0.0.1:52100/cb'];
        yield 'loopback v6' => ['http://[::1]:52100/cb'];
        yield 'localhost' => ['http://localhost:52100/cb'];
        yield 'private-use scheme' => ['com.example.mcpclient:/oauth/cb'];
        yield 'uppercase scheme' => ['HTTPS://client.example/cb'];
        yield 'uppercase loopback host' => ['http://LOCALHOST:52100/cb'];
        yield 'mixed-case private-use scheme' => ['Com.Example.McpClient:/oauth/cb'];
    }

    #[DataProvider('malformed')]
    public function testAMalformedUriIsRefusedEvenWhenAllowListed(string $uri): void
    {
        // The allow-list cannot vouch for a javascript: URI; well-formedness is
        // checked first and independently.
        $this->expectException(OAuthException::class);

        $this->server([$uri])->registerClient('Some Client', [$uri]);
    }

    #[DataProvider('wellFormed')]
    public function testAnAllowListedWellFormedUriIsAccepted(string $uri): void
    {
        $client = $this->server([$uri])->registerClient('Some Client', [$uri]);

        self::assertSame([$uri], $client->getRedirectUris());
    }

    /**
     * The finding itself: before the fix every one of these registered
     * successfully, whatever the configuration said.
     */
    #[DataProvider('wellFormed')]
    public function testAnEmptyAllowListRefusesEveryRegistration(string $uri): void
    {
        try {
            $this->server([])->registerClient('Some Client', [$uri]);
            self::fail('An empty allow-list must refuse the registration.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_redirect_uri', $exception->error);
            self::assertSame(
                'redirect_uri is not on the allow-list of this authorization server.',
                $exception->getMessage(),
            );
        }
    }

    public function testAnHttpsHostThatIsNotListedIsRefused(): void
    {
        $this->expectException(OAuthException::class);

        $this->server(['https://client.example/cb'])->registerClient('Evil', ['https://attacker.example/cb']);
    }

    /** @return iterable<string, array{string}> */
    public static function nearMisses(): iterable
    {
        yield 'longer path' => ['https://client.example/cb/extra'];
        yield 'shorter path' => ['https://client.example/'];
        yield 'trailing slash' => ['https://client.example/cb/'];
        yield 'added query' => ['https://client.example/cb?x=1'];
        yield 'different case' => ['https://Client.Example/cb'];
        yield 'explicit port on https' => ['https://client.example:8443/cb'];
        yield 'subdomain' => ['https://evil.client.example/cb'];
        yield 'suffix host' => ['https://client.example.attacker.example/cb'];
    }

    /**
     * Exact string matching (OAuth 2.1 §2.3.1): no prefix match, no wildcard,
     * no normalisation, and the port is significant for https.
     */
    #[DataProvider('nearMisses')]
    public function testOnlyTheExactStringMatches(string $uri): void
    {
        self::assertFalse((new RedirectUriPolicy(['https://client.example/cb']))->isAllowed($uri));
    }

    public function testAPrivateUseSchemeIsAcceptedOnlyWhenListed(): void
    {
        $policy = new RedirectUriPolicy(['com.example.mcpclient:/oauth/cb']);

        self::assertTrue($policy->isAllowed('com.example.mcpclient:/oauth/cb'));
        self::assertFalse($policy->isAllowed('com.attacker.app:/oauth/cb'));
        self::assertFalse((new RedirectUriPolicy([]))->isAllowed('com.example.mcpclient:/oauth/cb'));
    }

    /** RFC 8252 §7.3: a native client picks its port at request time. */
    public function testALoopbackEntryMatchesAnyPort(): void
    {
        $policy = new RedirectUriPolicy(['http://127.0.0.1/callback', 'http://[::1]/callback']);

        self::assertTrue($policy->isAllowed('http://127.0.0.1:52100/callback'));
        self::assertTrue($policy->isAllowed('http://127.0.0.1:1/callback'));
        self::assertTrue($policy->isAllowed('http://127.0.0.1/callback'));
        self::assertTrue($policy->isAllowed('http://[::1]:8080/callback'));
    }

    public function testAPortOnTheLoopbackEntryDoesNotPinIt(): void
    {
        self::assertTrue((new RedirectUriPolicy(['http://127.0.0.1:3000/cb']))->isAllowed('http://127.0.0.1:52100/cb'));
    }

    public function testALoopbackEntryIgnoresOnlyThePort(): void
    {
        $policy = new RedirectUriPolicy(['http://127.0.0.1/callback']);

        self::assertFalse($policy->isAllowed('http://127.0.0.1:52100/other'), 'path is significant');
        self::assertFalse($policy->isAllowed('http://127.0.0.1:52100/callback?x=1'), 'query is significant');
        self::assertFalse($policy->isAllowed('http://localhost:52100/callback'), 'localhost is not 127.0.0.1');
        self::assertFalse($policy->isAllowed('http://[::1]:52100/callback'), '[::1] is not 127.0.0.1');
        self::assertFalse($policy->isAllowed('https://127.0.0.1:52100/callback'), 'scheme is significant');
        self::assertFalse($policy->isAllowed('http://127.0.0.1:52100@attacker.example/callback'), 'userinfo trick');
    }

    public function testLoopbackIsNotImplicitlyAllowed(): void
    {
        // Before the fix loopback was always accepted. It now needs an entry
        // like any other redirect URI.
        self::assertFalse((new RedirectUriPolicy(['https://client.example/cb']))->isAllowed('http://127.0.0.1:52100/cb'));
    }

    public function testEmptyEntriesInTheConfigurationAreIgnored(): void
    {
        self::assertFalse((new RedirectUriPolicy(['']))->isAllowed(''));
    }

    /**
     * Plain http off-loopback must fail for the reason stated, not merely fail.
     */
    public function testPlainHttpOffLoopbackNamesTheReason(): void
    {
        try {
            RedirectUriPolicy::assertWellFormed('http://attacker.example/cb');
            self::fail('Expected the URI to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_redirect_uri', $exception->error);
            self::assertSame(
                'Plain http is only allowed on the loopback interface; use https.',
                $exception->getMessage(),
            );
        }
    }

    /**
     * One bad entry poisons the whole registration: a client that keeps a valid
     * URI alongside a refused one would still be able to use the refused one.
     */
    public function testOneRefusedUriRejectsTheWholeRegistration(): void
    {
        $this->expectException(OAuthException::class);

        $this->server(['https://client.example/cb'])->registerClient('Some Client', [
            'https://client.example/cb',
            'https://attacker.example/cb',
        ]);
    }

    public function testTheServerExposesTheAllowListDecisionForTheAuthorizeEndpoint(): void
    {
        $server = $this->server(['https://client.example/cb']);

        self::assertTrue($server->isRedirectUriAllowed('https://client.example/cb'));
        self::assertFalse($server->isRedirectUriAllowed('https://attacker.example/cb'));
    }

    public function testAServerWithoutAPolicyAllowsNothing(): void
    {
        $em = $this->createStub(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($this->createStub(EntityRepository::class));

        $this->expectException(OAuthException::class);

        (new OAuthServer($em))->registerClient('Some Client', ['https://client.example/cb']);
    }

    /** @param list<string> $allowed */
    private function server(array $allowed): OAuthServer
    {
        $em = $this->createStub(EntityManagerInterface::class);
        $em->method('getRepository')->willReturn($this->createStub(EntityRepository::class));

        return new OAuthServer($em, null, new RedirectUriPolicy($allowed));
    }
}
