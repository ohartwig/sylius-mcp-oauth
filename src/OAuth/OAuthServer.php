<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Psr\Log\LoggerInterface;

/**
 * OAuth 2.1 authorization-server logic for the MCP endpoint: Dynamic Client
 * Registration (RFC 7591), authorization-code issuance/consumption with
 * mandatory PKCE S256 (RFC 7636). Access-token minting is delegated to
 * {@see AccessTokenManager}. Endpoints (controllers) stay thin over this.
 */
final class OAuthServer
{
    /** Authorization codes are short-lived (seconds). */
    private const CODE_TTL = 300;

    /** OAuth-issued access tokens live 90 days (revocable in the admin UI). */
    public const TOKEN_TTL_DAYS = 90;

    public const SUPPORTED_SCOPES = ['mcp'];

    /** @var EntityRepository<McpOAuthClient> */
    private EntityRepository $clients;

    /** @var EntityRepository<McpAuthorizationCode> */
    private EntityRepository $codes;

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->clients = $entityManager->getRepository(McpOAuthClient::class);
        $this->codes = $entityManager->getRepository(McpAuthorizationCode::class);
    }

    /**
     * Register a public client (RFC 7591). Only PKCE public clients are allowed.
     *
     * @param list<string> $redirectUris
     */
    public function registerClient(string $clientName, array $redirectUris): McpOAuthClient
    {
        if ($redirectUris === []) {
            throw new OAuthException('invalid_client_metadata', 'At least one redirect_uri is required.');
        }
        foreach ($redirectUris as $uri) {
            self::assertUsableRedirectUri($uri);
        }

        $client = new McpOAuthClient(
            clientId: 'mcpc_' . bin2hex(random_bytes(16)),
            clientName: $clientName !== '' ? mb_substr($clientName, 0, 191) : 'MCP Client',
            redirectUris: $redirectUris,
        );

        $this->entityManager->persist($client);
        $this->entityManager->flush();

        return $client;
    }

    public function findClient(string $clientId): ?McpOAuthClient
    {
        return $this->clients->findOneBy(['clientId' => $clientId]);
    }

    /**
     * Issue an authorization code after the admin user consents. Returns the RAW
     * code (only its hash is stored).
     *
     * @param list<string> $scopes
     */
    public function issueCode(
        McpOAuthClient $client,
        int $adminUserId,
        string $redirectUri,
        array $scopes,
        string $codeChallenge,
        string $codeChallengeMethod,
    ): string {
        $raw = bin2hex(random_bytes(32));

        $code = new McpAuthorizationCode(
            codeHash: hash('sha256', $raw),
            clientId: $client->getClientId(),
            adminUserId: $adminUserId,
            redirectUri: $redirectUri,
            scopes: $scopes,
            codeChallenge: $codeChallenge,
            codeChallengeMethod: $codeChallengeMethod,
            expiresAt: (new \DateTimeImmutable())->modify(sprintf('+%d seconds', self::CODE_TTL)),
        );

        $this->entityManager->persist($code);
        $this->entityManager->flush();

        return $raw;
    }

    /**
     * Validate + consume an authorization code at the token endpoint. Verifies
     * the code is usable, bound to this client + redirect URI, and that the PKCE
     * verifier matches. Marks the code used. Returns the code payload.
     *
     * @return array{admin_user_id: int, scopes: list<string>, client: McpOAuthClient}
     */
    public function consumeCode(
        string $rawCode,
        string $clientId,
        string $redirectUri,
        string $codeVerifier,
    ): array {
        $code = $this->codes->findOneBy(['codeHash' => hash('sha256', $rawCode)]);
        if (!$code instanceof McpAuthorizationCode || !$code->isUsable()) {
            throw new OAuthException('invalid_grant', 'Authorization code is invalid, expired or already used.');
        }
        if (!hash_equals($code->getClientId(), $clientId)) {
            throw new OAuthException('invalid_grant', 'Authorization code was issued to a different client.');
        }
        if (!hash_equals($code->getRedirectUri(), $redirectUri)) {
            throw new OAuthException('invalid_grant', 'redirect_uri does not match the authorization request.');
        }
        if (!$this->verifyPkce($codeVerifier, $code->getCodeChallenge())) {
            throw new OAuthException('invalid_grant', 'PKCE verification failed.');
        }

        $client = $this->findClient($clientId);
        if (!$client instanceof McpOAuthClient) {
            throw new OAuthException('invalid_client', 'Unknown client.');
        }

        // Burn the code in a single conditional UPDATE rather than
        // read-then-write. isUsable() above is a read, and two token requests
        // carrying the same code can both pass it before either writes — which
        // would mint two access tokens from one authorization. Letting the
        // database decide the winner closes that window without a lock.
        $burned = $this->entityManager->createQuery(
            \sprintf('UPDATE %s c SET c.used = true WHERE c.codeHash = :hash AND c.used = false', McpAuthorizationCode::class),
        )->setParameter('hash', hash('sha256', $rawCode))->execute();

        if (1 !== $burned) {
            // Reaching here means the code was valid a moment ago and is now
            // spent — someone else redeemed it in between. With PKCE S256
            // mandatory an intercepted code is useless without the verifier, so
            // this is far more likely a client retrying than an attack. It is
            // still the one signal that would distinguish the two, and it was
            // previously invisible.
            //
            // OAuth 2.1 also says a server SHOULD revoke tokens already issued
            // from a replayed code. That needs a token-to-code link the schema
            // does not have. If this ever fires in production, that is the
            // evidence to add it — until then it would be a migration bought on
            // suspicion.
            $this->logger?->warning('MCP OAuth: authorization code redeemed twice', [
                'client_id' => $clientId,
                // Prefix only: the full hash is the lookup key for a live code.
                'code_hash_prefix' => substr(hash('sha256', $rawCode), 0, 12),
            ]);

            throw new OAuthException('invalid_grant', 'Authorization code is invalid, expired or already used.');
        }

        // The UPDATE bypassed the identity map, so the in-memory entity still
        // says unused. Leaving it that way would let a second consumeCode() in
        // the same request pass isUsable().
        $code->markUsed();

        return ['admin_user_id' => $code->getAdminUserId(), 'scopes' => $code->getScopes(), 'client' => $client];
    }

    /**
     * OAuth 2.1 §2.3.1 / RFC 8252 §7: a redirect URI is https, http on the
     * loopback interface, or a private-use scheme.
     *
     * FILTER_VALIDATE_URL is not a substitute. It accepts `javascript://x%0a…`,
     * `file:///etc/passwd` and `ftp://…` — and since registration is open by
     * design (public clients, no secret), anyone could register a client whose
     * redirect target is one of those and get it echoed into a Location header.
     *
     * A fragment is rejected outright: RFC 6749 §3.1.2 forbids it, and the
     * authorization response appends its own query, which a fragment would
     * swallow.
     */
    private static function assertUsableRedirectUri(string $uri): void
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'])) {
            throw new OAuthException('invalid_redirect_uri', 'redirect_uri is not a valid URL.');
        }
        if (isset($parts['fragment'])) {
            throw new OAuthException('invalid_redirect_uri', 'redirect_uri must not contain a fragment.');
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host'] ?? '');

        if ($scheme === 'https') {
            if ($host === '') {
                throw new OAuthException('invalid_redirect_uri', 'redirect_uri must name a host.');
            }

            return;
        }

        if ($scheme === 'http') {
            // RFC 8252 §7.3: loopback only, and only for native clients.
            if (\in_array($host, ['127.0.0.1', '::1', '[::1]', 'localhost'], true)) {
                return;
            }

            throw new OAuthException(
                'invalid_redirect_uri',
                'Plain http is only allowed on the loopback interface; use https.',
            );
        }

        // RFC 8252 §7.1: a private-use scheme is a reverse-domain name, so it
        // always contains a dot. That excludes javascript:, data:, file: and ftp:
        // without needing to enumerate them.
        if (str_contains($scheme, '.')) {
            return;
        }

        throw new OAuthException(
            'invalid_redirect_uri',
            \sprintf('Scheme "%s" is not allowed for a redirect_uri.', $scheme),
        );
    }

    /** PKCE S256 (RFC 7636): base64url(sha256(verifier)) == stored challenge. */
    private function verifyPkce(string $verifier, string $challenge): bool
    {
        if ($verifier === '') {
            return false;
        }

        $computed = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return hash_equals($challenge, $computed);
    }
}
