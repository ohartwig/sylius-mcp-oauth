<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

use Koh\SyliusMcpOAuth\Entity\McpAuthorizationCode;
use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;

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
            if (!\is_string($uri) || filter_var($uri, \FILTER_VALIDATE_URL) === false) {
                throw new OAuthException('invalid_redirect_uri', 'redirect_uri is not a valid URL.');
            }
        }

        $client = new McpOAuthClient(
            clientId: 'mcpc_' . bin2hex(random_bytes(16)),
            clientName: $clientName !== '' ? mb_substr($clientName, 0, 191) : 'MCP Client',
            redirectUris: array_values($redirectUris),
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

        $code->markUsed();
        $this->entityManager->flush();

        return ['admin_user_id' => $code->getAdminUserId(), 'scopes' => $code->getScopes(), 'client' => $client];
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
