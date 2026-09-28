<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The authorization-code exchange is the moment a browser redirect becomes an
 * admin-scoped access token. Registration is open by design — public clients,
 * no secret — so the only things standing between an attacker and a token are
 * the PKCE verifier and the bindings to client and redirect URI. Each of those
 * checks is asserted here on its own, because any one of them silently passing
 * would be enough.
 */
#[CoversClass(OAuthServer::class)]
final class CodeExchangeTest extends TestCase
{
    private const VERIFIER = 'a-verifier-long-enough-to-be-realistic-0123456789';
    private const CLIENT_ID = 'mcpc_abc';
    private const REDIRECT_URI = 'https://client.example/cb';
    private const RAW_CODE = 'raw-code';

    /**
     * The code lookup is keyed on the hash of the presented raw code, not on
     * an arbitrary/empty filter that any stored code would satisfy — that
     * distinction is what makes a code single-use and code-specific at all.
     */
    public function testConsumeCodeLooksUpByTheHashedCodeSpecifically(): void
    {
        $codes = $this->createMock(EntityRepository::class);
        $codes->expects(self::once())
            ->method('findOneBy')
            ->with(['codeHash' => hash('sha256', self::RAW_CODE)])
            ->willReturn(null);

        $clients = $this->createStub(EntityRepository::class);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturnCallback(
            static fn (string $class): EntityRepository => McpAuthorizationCode::class === $class ? $codes : $clients,
        );

        try {
            (new OAuthServer($entityManager))->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused (no code was returned).');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAValidExchangeReturnsTheAuthorisedAdminAndScopes(): void
    {
        $result = $this->server()->consumeCode(
            self::RAW_CODE,
            self::CLIENT_ID,
            self::REDIRECT_URI,
            self::VERIFIER,
        );

        self::assertSame(7, $result['admin_user_id']);
        self::assertSame(['mcp'], $result['scopes']);
        self::assertInstanceOf(McpOAuthClient::class, $result['client']);
    }

    public function testAWrongPkceVerifierIsRefused(): void
    {
        // Without this check an intercepted authorization code would be enough
        // to obtain a token, which is the entire attack PKCE exists to stop.
        try {
            $this->server()->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                'not-the-verifier-that-was-used',
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
            self::assertStringContainsString('PKCE', $exception->getMessage());
        }
    }

    public function testAnEmptyPkceVerifierIsRefused(): void
    {
        // An empty verifier must not be treated as "no PKCE required".
        try {
            $this->server()->consumeCode(self::RAW_CODE, self::CLIENT_ID, self::REDIRECT_URI, '');
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAVerifierThatIsAPrefixOfTheRealOneIsRefused(): void
    {
        try {
            $this->server()->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                substr(self::VERIFIER, 0, 10),
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAStoredChallengeThatIsMerelyAPrefixOfTheComputedOneIsRefused(): void
    {
        // The comparison must be exact and length-sensitive. A prefix match
        // would collapse the challenge to a few bytes of entropy, which is
        // brute-forcible, and no ordinary wrong verifier would reveal it.
        $truncated = substr($this->challenge(), 0, 4);

        try {
            $this->server(code: $this->code(codeChallenge: $truncated))
                ->consumeCode(self::RAW_CODE, self::CLIENT_ID, self::REDIRECT_URI, self::VERIFIER);
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAnEmptyVerifierIsRefusedEvenAgainstTheChallengeOfTheEmptyString(): void
    {
        // Without the explicit empty-verifier guard, a code registered with the
        // challenge of the empty string would be redeemable by sending no
        // verifier at all. The guard is what makes that unreachable rather than
        // merely unlikely.
        $challengeOfEmpty = rtrim(strtr(base64_encode(hash('sha256', '', true)), '+/', '-_'), '=');

        try {
            $this->server(code: $this->code(codeChallenge: $challengeOfEmpty))
                ->consumeCode(self::RAW_CODE, self::CLIENT_ID, self::REDIRECT_URI, '');
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testACodeIssuedToAnotherClientIsRefused(): void
    {
        // Codes are handed to a client through a redirect. Without this binding
        // a client that observed another's code could redeem it as its own.
        try {
            $this->server()->consumeCode(
                self::RAW_CODE,
                'mcpc_someone_else',
                self::REDIRECT_URI,
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
            self::assertStringContainsString('different client', $exception->getMessage());
        }
    }

    public function testAMismatchedRedirectUriIsRefused(): void
    {
        try {
            $this->server()->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                'https://client.example/other-callback',
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
            self::assertStringContainsString('redirect_uri', $exception->getMessage());
        }
    }

    public function testAnUnknownCodeIsRefused(): void
    {
        try {
            $this->server(withCode: false)->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAnExpiredCodeIsRefused(): void
    {
        // Codes live seconds. An expired one that still worked would widen the
        // window in which an intercepted redirect is useful.
        try {
            $this->server(code: $this->code(expiresAt: new \DateTimeImmutable('-1 second')))
                ->consumeCode(self::RAW_CODE, self::CLIENT_ID, self::REDIRECT_URI, self::VERIFIER);
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testAnAlreadyUsedCodeIsRefused(): void
    {
        $code = $this->code();
        $code->markUsed();

        try {
            $this->server(code: $code)->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_grant', $exception->error);
        }
    }

    public function testTheInMemoryCodeIsMarkedUsedAfterTheBurn(): void
    {
        // The conditional UPDATE bypasses the identity map, so the entity still
        // reads as unused. Leaving it that way would let a second consumeCode()
        // in the same request pass the usability check.
        $code = $this->code();

        $this->server(code: $code)->consumeCode(
            self::RAW_CODE,
            self::CLIENT_ID,
            self::REDIRECT_URI,
            self::VERIFIER,
        );

        self::assertFalse($code->isUsable());
    }

    public function testAValidCodeForAClientThatHasSinceVanishedIsRefused(): void
    {
        // Deleting a client must invalidate codes already issued to it.
        try {
            $this->server(withClient: false)->consumeCode(
                self::RAW_CODE,
                self::CLIENT_ID,
                self::REDIRECT_URI,
                self::VERIFIER,
            );
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_client', $exception->error);
        }
    }

    public function testRegisteringAClientMintsAnIdentifierAndKeepsTheRedirectUris(): void
    {
        $persisted = null;
        $server = $this->server(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $client = $server->registerClient('My Client', [self::REDIRECT_URI]);

        self::assertSame($persisted, $client);
        self::assertStringStartsWith('mcpc_', $client->getClientId());
        self::assertSame([self::REDIRECT_URI], $client->getRedirectUris());
    }

    /**
     * 16 random bytes, hex-encoded. A shorter identifier would be enumerable —
     * client_id is not treated as a secret anywhere else in this bundle.
     */
    public function testTheClientIdCarriesEnoughEntropyToResistGuessing(): void
    {
        $clientId = $this->server()->registerClient('My Client', [self::REDIRECT_URI])->getClientId();

        self::assertMatchesRegularExpression('/^mcpc_[0-9a-f]{32}$/', $clientId);
    }

    public function testRegisteringAClientFlushesIt(): void
    {
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $entityManager->expects(self::once())->method('flush');

        (new OAuthServer($entityManager))->registerClient('My Client', [self::REDIRECT_URI]);
    }

    /**
     * findClient() is called from AuthorizeController, outside this class, so
     * it has to stay part of the public API — and the lookup has to be keyed
     * on the client_id actually asked for, not on an arbitrary/empty filter
     * that would let any registered client answer for any requested id.
     */
    public function testFindClientIsCallableFromOutsideTheClassAndFiltersByTheRequestedId(): void
    {
        $wanted = new McpOAuthClient(self::CLIENT_ID, 'Wanted', [self::REDIRECT_URI]);
        $other = new McpOAuthClient('mcpc_other', 'Other', [self::REDIRECT_URI]);
        $byId = ['mcpc_other' => $other, self::CLIENT_ID => $wanted];

        $clients = $this->createStub(EntityRepository::class);
        $clients->method('findOneBy')->willReturnCallback(
            static fn (array $criteria): ?McpOAuthClient => $byId[$criteria['clientId']] ?? null,
        );

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($clients);

        $server = new OAuthServer($entityManager);

        self::assertSame($wanted, $server->findClient(self::CLIENT_ID));
        self::assertNull($server->findClient('mcpc_unknown'));
    }

    public function testTwoRegistrationsNeverShareAClientIdentifier(): void
    {
        $server = $this->server();

        self::assertNotSame(
            $server->registerClient('A', [self::REDIRECT_URI])->getClientId(),
            $server->registerClient('B', [self::REDIRECT_URI])->getClientId(),
        );
    }

    public function testRegisteringWithoutARedirectUriIsRefused(): void
    {
        // A client with nowhere to send the code cannot complete a flow, and an
        // empty list would otherwise pass the per-URI validation vacuously.
        try {
            $this->server()->registerClient('My Client', []);
            self::fail('Expected the registration to be refused.');
        } catch (OAuthException $exception) {
            self::assertSame('invalid_client_metadata', $exception->error);
        }
    }

    public function testAnEmptyClientNameFallsBackToAPlaceholder(): void
    {
        $client = $this->server()->registerClient('', [self::REDIRECT_URI]);

        self::assertSame('MCP Client', $client->getClientName());
    }

    public function testAnOverlongClientNameIsTruncatedToTheColumnLength(): void
    {
        $client = $this->server()->registerClient(str_repeat('n', 500), [self::REDIRECT_URI]);

        self::assertSame(191, mb_strlen($client->getClientName()));
    }

    /**
     * Truncation must count *characters*, not bytes, and it must keep the
     * first character rather than skip it.
     *
     * A name of nothing but 2-byte UTF-8 characters makes a byte-based cut
     * (substr() instead of mb_substr()) both shorter in character count and
     * invalid UTF-8 at the boundary — either is a real, user-visible corruption
     * of a shop's own client name, not merely a coverage gap.
     */
    public function testAnOverlongMultibyteClientNameIsTruncatedByCharacterFromTheStart(): void
    {
        $name = 'A' . str_repeat('ü', 300);

        $client = $this->server()->registerClient($name, [self::REDIRECT_URI]);

        self::assertSame('A' . str_repeat('ü', 190), $client->getClientName());
    }

    /** 32 random bytes, hex-encoded. A shorter code would be enumerable. */
    public function testTheIssuedCodeCarriesEnoughEntropyToResistGuessing(): void
    {
        $raw = $this->server()->issueCode(
            new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI]),
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $this->challenge(),
            codeChallengeMethod: 'S256',
        );

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $raw);
    }

    public function testIssuingACodeFlushesIt(): void
    {
        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $entityManager->expects(self::once())->method('flush');

        (new OAuthServer($entityManager))->issueCode(
            new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI]),
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $this->challenge(),
            codeChallengeMethod: 'S256',
        );
    }

    public function testIssuingACodeReturnsTheRawValueAndStoresOnlyItsHash(): void
    {
        // The raw code travels in a redirect URL and ends up in browser history
        // and server logs; storing it would make those logs credentials.
        $persisted = null;
        $server = $this->server(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $raw = $server->issueCode(
            new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI]),
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $this->challenge(),
            codeChallengeMethod: 'S256',
        );

        self::assertInstanceOf(McpAuthorizationCode::class, $persisted);
        self::assertNotSame($raw, $persisted->getCodeHash());
        self::assertSame(hash('sha256', $raw), $persisted->getCodeHash());
    }

    public function testAnIssuedCodeIsShortLived(): void
    {
        // Five minutes. A long-lived code keeps an intercepted redirect useful.
        $persisted = null;
        $server = $this->server(persistCallback: function (object $entity) use (&$persisted): void {
            $persisted = $entity;
        });

        $server->issueCode(
            new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI]),
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $this->challenge(),
            codeChallengeMethod: 'S256',
        );

        self::assertInstanceOf(McpAuthorizationCode::class, $persisted);
        // The entity exposes no expiry getter, so the window is asserted through
        // the behaviour that depends on it.
        self::assertTrue($persisted->isUsable(new \DateTimeImmutable('+299 seconds')));
        self::assertFalse($persisted->isUsable(new \DateTimeImmutable('+301 seconds')));
    }

    public function testTwoIssuedCodesAreNeverTheSame(): void
    {
        $server = $this->server();
        $client = new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI]);

        $first = $server->issueCode($client, 7, self::REDIRECT_URI, ['mcp'], $this->challenge(), 'S256');
        $second = $server->issueCode($client, 7, self::REDIRECT_URI, ['mcp'], $this->challenge(), 'S256');

        self::assertNotSame($first, $second);
    }

    // --- helpers -------------------------------------------------------------

    private function challenge(string $verifier = self::VERIFIER): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function code(?\DateTimeImmutable $expiresAt = null, ?string $codeChallenge = null): McpAuthorizationCode
    {
        return new McpAuthorizationCode(
            codeHash: hash('sha256', self::RAW_CODE),
            clientId: self::CLIENT_ID,
            adminUserId: 7,
            redirectUri: self::REDIRECT_URI,
            scopes: ['mcp'],
            codeChallenge: $codeChallenge ?? $this->challenge(),
            codeChallengeMethod: 'S256',
            expiresAt: $expiresAt ?? (new \DateTimeImmutable())->modify('+300 seconds'),
        );
    }

    private function server(
        ?McpAuthorizationCode $code = null,
        ?McpOAuthClient $client = null,
        int $burned = 1,
        ?\Closure $persistCallback = null,
        bool $withCode = true,
        bool $withClient = true,
    ): OAuthServer {
        $codes = $this->createStub(EntityRepository::class);
        $codes->method('findOneBy')->willReturn($withCode ? ($code ?? $this->code()) : null);

        $clients = $this->createStub(EntityRepository::class);
        $clients->method('findOneBy')->willReturn(
            $withClient ? ($client ?? new McpOAuthClient(self::CLIENT_ID, 'Client', [self::REDIRECT_URI])) : null,
        );

        $query = $this->createStub(Query::class);
        $query->method('setParameter')->willReturnSelf();
        $query->method('execute')->willReturn($burned);

        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturnCallback(
            static fn (string $class): EntityRepository => McpAuthorizationCode::class === $class ? $codes : $clients,
        );
        $entityManager->method('createQuery')->willReturn($query);

        if ($persistCallback !== null) {
            $entityManager->method('persist')->willReturnCallback($persistCallback);
        }

        return new OAuthServer($entityManager);
    }
}
