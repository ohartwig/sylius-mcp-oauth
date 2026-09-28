<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;

/**
 * Mints and validates {@see McpAccessToken}s. Raw tokens are `tbmcp_<random>`;
 * only their SHA-256 hash is stored, so lookups hash the presented token and
 * compare. The raw value is returned by {@see create()} once and never again.
 */
final class AccessTokenManager
{
    private const PREFIX = 'tbmcp_';

    /** @var EntityRepository<McpAccessToken> */
    private EntityRepository $repository;

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
    ) {
        $this->repository = $entityManager->getRepository(McpAccessToken::class);
    }

    /**
     * Create a token for an admin user. Returns the RAW token (show once) and
     * the persisted entity.
     *
     * @param list<string> $scopes
     *
     * @return array{token: string, entity: McpAccessToken}
     */
    public function create(
        int $adminUserId,
        string $name,
        array $scopes = ['mcp'],
        ?\DateTimeImmutable $expiresAt = null,
        ?string $clientId = null,
    ): array {
        $raw = self::PREFIX . bin2hex(random_bytes(32));

        $entity = new McpAccessToken(
            tokenHash: self::hash($raw),
            adminUserId: $adminUserId,
            name: $name,
            scopes: $scopes,
            expiresAt: $expiresAt,
            clientId: $clientId,
        );

        $this->entityManager->persist($entity);
        $this->entityManager->flush();

        return ['token' => $raw, 'entity' => $entity];
    }

    /**
     * Resolve a raw bearer token to a valid, non-revoked, non-expired token
     * entity, or null. Updates last-used on success.
     */
    public function findValid(string $rawToken): ?McpAccessToken
    {
        if ($rawToken === '' || !str_starts_with($rawToken, self::PREFIX)) {
            return null;
        }

        $token = $this->repository->findOneBy(['tokenHash' => self::hash($rawToken)]);
        if (!$token instanceof McpAccessToken || !$token->isValid()) {
            return null;
        }

        $token->touch();
        $this->entityManager->flush();

        return $token;
    }

    public function find(int $id): ?McpAccessToken
    {
        return $this->repository->find($id);
    }

    /** @return list<McpAccessToken> */
    public function findForAdminUser(int $adminUserId): array
    {
        /** @var list<McpAccessToken> $tokens */
        $tokens = $this->repository->findBy(['adminUserId' => $adminUserId], ['createdAt' => 'DESC']);

        return $tokens;
    }

    public function revoke(McpAccessToken $token): void
    {
        $token->revoke();
        $this->entityManager->flush();
    }

    /**
     * Revoke by raw token (RFC 7009). No-op if unknown — the endpoint always
     * reports success either way.
     */
    public function revokeRaw(string $rawToken): void
    {
        if ($rawToken === '' || !str_starts_with($rawToken, self::PREFIX)) {
            return;
        }

        $token = $this->repository->findOneBy(['tokenHash' => self::hash($rawToken)]);
        if ($token instanceof McpAccessToken) {
            $this->revoke($token);
        }
    }

    private static function hash(string $rawToken): string
    {
        return hash('sha256', $rawToken);
    }
}
