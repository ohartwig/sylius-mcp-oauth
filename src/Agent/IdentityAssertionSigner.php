<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

/**
 * The service-signed `identity_assertion` of auth.md: a compact JWS (HS256)
 * that only this server issues and only this server verifies, at its own token
 * endpoint (RFC 7523 jwt-bearer grant). A symmetric key is therefore enough;
 * it is derived from the application secret, so no key has to be configured.
 *
 * Verification accepts nothing but HS256 with the expected `typ`: no `none`,
 * no algorithm chosen by the token.
 */
final class IdentityAssertionSigner
{
    public const TYPE = 'agent-identity+jwt';

    private readonly string $key;

    public function __construct(string $secret)
    {
        if ('' === $secret) {
            throw new \InvalidArgumentException('The identity assertion key needs a non-empty application secret.');
        }

        $this->key = hash_hmac('sha256', 'koh_mcp_oauth.agent_identity_assertion', $secret, true);
    }

    /** @param array<string, scalar|null> $claims */
    public function sign(array $claims): string
    {
        $input = self::encode(['alg' => 'HS256', 'typ' => self::TYPE]).'.'.self::encode($claims);

        return $input.'.'.self::base64url(hash_hmac('sha256', $input, $this->key, true));
    }

    /**
     * The claims of a token this server signed, or null for anything else —
     * a foreign signature, another algorithm, a malformed token. Expiry is the
     * caller's to check.
     *
     * @return array<string, mixed>|null
     */
    public function verify(string $token): ?array
    {
        $parts = explode('.', $token);
        if (3 !== \count($parts)) {
            return null;
        }
        [$header, $payload, $signature] = $parts;

        $expected = self::base64url(hash_hmac('sha256', $header.'.'.$payload, $this->key, true));
        if (!hash_equals($expected, $signature)) {
            return null;
        }

        $decodedHeader = self::decode($header);
        if (null === $decodedHeader || 'HS256' !== ($decodedHeader['alg'] ?? null) || self::TYPE !== ($decodedHeader['typ'] ?? null)) {
            return null;
        }

        return self::decode($payload);
    }

    /** @param array<string, mixed> $data */
    private static function encode(array $data): string
    {
        return self::base64url(json_encode($data, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
    }

    /** @return array<string, mixed>|null */
    private static function decode(string $segment): ?array
    {
        $json = base64_decode(strtr($segment, '-_', '+/'), true);
        if (false === $json) {
            return null;
        }

        try {
            $data = json_decode($json, true, 8, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (!\is_array($data)) {
            return null;
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
