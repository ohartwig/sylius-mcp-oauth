<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Agent;

use Koh\SyliusMcpOAuth\Agent\IdentityAssertionSigner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The identity assertion is the agent's key to new access tokens. Only a
 * token this server signed, with HS256 and the expected type, may verify.
 */
#[CoversClass(IdentityAssertionSigner::class)]
final class IdentityAssertionSignerTest extends TestCase
{
    public function testARoundTripKeepsTheClaims(): void
    {
        $signer = new IdentityAssertionSigner('secret');
        $token = $signer->sign(['sub' => 'reg_1', 'exp' => 123, 'claimed' => true, 'iss' => 'https://shop.example/x']);

        self::assertSame(['sub' => 'reg_1', 'exp' => 123, 'claimed' => true, 'iss' => 'https://shop.example/x'], $signer->verify($token));
        self::assertStringNotContainsString('\/', (string) base64_decode(strtr(explode('.', $token)[1], '-_', '+/'), true));
        self::assertStringNotContainsString('=', $token);

        $header = json_decode((string) base64_decode(strtr(explode('.', $token)[0], '-_', '+/'), true), true);
        self::assertSame(['alg' => 'HS256', 'typ' => 'agent-identity+jwt'], $header);
    }

    public function testTheSignatureIsAnHmacOverHeaderAndPayload(): void
    {
        $token = (new IdentityAssertionSigner('secret'))->sign(['sub' => 'x']);
        [$header, $payload, $signature] = explode('.', $token);
        $key = hash_hmac('sha256', 'koh_mcp_oauth.agent_identity_assertion', 'secret', true);

        self::assertSame(rtrim(strtr(base64_encode(hash_hmac('sha256', $header.'.'.$payload, $key, true)), '+/', '-_'), '='), $signature);
    }

    public function testATokenOfAnotherKeyDoesNotVerify(): void
    {
        $token = (new IdentityAssertionSigner('other'))->sign(['sub' => 'reg_1']);

        self::assertNull((new IdentityAssertionSigner('secret'))->verify($token));
    }

    public function testATamperedPayloadDoesNotVerify(): void
    {
        $signer = new IdentityAssertionSigner('secret');
        [$header, , $signature] = explode('.', $signer->sign(['sub' => 'reg_1', 'claimed' => false]));
        $payload = rtrim(strtr(base64_encode('{"sub":"reg_1","claimed":true}'), '+/', '-_'), '=');

        self::assertNull($signer->verify($header.'.'.$payload.'.'.$signature));
    }

    /** @return iterable<string, array{array<string, string>}> */
    public static function foreignHeaders(): iterable
    {
        yield 'alg none' => [['alg' => 'none', 'typ' => 'agent-identity+jwt']];
        yield 'another algorithm' => [['alg' => 'HS512', 'typ' => 'agent-identity+jwt']];
        yield 'another type' => [['alg' => 'HS256', 'typ' => 'JWT']];
        yield 'no type' => [['alg' => 'HS256']];
    }

    /**
     * Even correctly signed, a header naming something else is refused — the
     * token does not get to choose how it is checked.
     *
     * @param array<string, string> $header
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('foreignHeaders')]
    public function testOnlyTheExpectedHeaderVerifies(array $header): void
    {
        $key = hash_hmac('sha256', 'koh_mcp_oauth.agent_identity_assertion', 'secret', true);
        $encode = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $input = $encode(json_encode($header, \JSON_THROW_ON_ERROR)).'.'.$encode('{"sub":"reg_1"}');

        self::assertNull((new IdentityAssertionSigner('secret'))->verify($input.'.'.$encode(hash_hmac('sha256', $input, $key, true))));
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => [''];
        yield 'two parts' => ['a.b'];
        yield 'four parts' => ['a.b.c.d'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformed')]
    public function testMalformedTokensDoNotVerify(string $token): void
    {
        self::assertNull((new IdentityAssertionSigner('secret'))->verify($token));
    }

    /** Signed garbage — not base64, not JSON, not an object — is still refused. */
    public function testSignedNonsenseDoesNotVerify(): void
    {
        $key = hash_hmac('sha256', 'koh_mcp_oauth.agent_identity_assertion', 'secret', true);
        $encode = static fn (string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $header = $encode('{"alg":"HS256","typ":"agent-identity+jwt"}');
        $signer = new IdentityAssertionSigner('secret');

        foreach (['!!!', $encode('not json'), $encode('"a string"'), $encode('[[[[[[[[[[1]]]]]]]]]]')] as $payload) {
            $input = $header.'.'.$payload;
            self::assertNull($signer->verify($input.'.'.$encode(hash_hmac('sha256', $input, $key, true))));
        }
        foreach (['!!!', $encode('not json')] as $badHeader) {
            $input = $badHeader.'.'.$encode('{"sub":"x"}');
            self::assertNull($signer->verify($input.'.'.$encode(hash_hmac('sha256', $input, $key, true))));
        }
    }

    public function testAnEmptySecretIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new IdentityAssertionSigner('');
    }
}
