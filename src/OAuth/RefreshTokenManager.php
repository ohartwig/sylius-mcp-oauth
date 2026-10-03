<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Entity\McpRefreshToken;
use Psr\Log\LoggerInterface;

/**
 * Refresh tokens with rotation and reuse detection (OAuth 2.1 §4.3.1).
 *
 * Without refresh tokens an operator chooses between short access tokens and
 * hourly re-consent, and in practice chooses long access tokens. With them,
 * the access token can stay short: the client trades its refresh token for a
 * new pair, and the old refresh token is spent.
 *
 * MCP clients are public clients, so a refresh token is a bearer credential
 * with no client authentication behind it. Rotation is the compensating
 * control: a refresh token works once. If a spent one comes back, either the
 * client or a thief is replaying it, the server cannot tell which, and the
 * whole family — every refresh and access token descended from the same
 * authorization — is revoked. The legitimate client then re-authorises; the
 * thief is left with nothing.
 */
final class RefreshTokenManager
{
    public const PREFIX = 'tbmcpr_';

    /** @var EntityRepository<McpRefreshToken> */
    private EntityRepository $repository;

    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly ?LoggerInterface $logger = null,
    ) {
        $this->repository = $entityManager->getRepository(McpRefreshToken::class);
    }

    public static function newFamily(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * @param list<string> $scopes
     *
     * @return array{token: string, entity: McpRefreshToken}
     */
    public function issue(string $family, int $adminUserId, string $clientId, array $scopes, ?string $audience, int $ttl): array
    {
        $raw = self::PREFIX.bin2hex(random_bytes(32));
        $entity = new McpRefreshToken(
            tokenHash: hash('sha256', $raw),
            family: $family,
            adminUserId: $adminUserId,
            clientId: $clientId,
            scopes: $scopes,
            audience: $audience,
            expiresAt: (new \DateTimeImmutable())->modify(\sprintf('+%d seconds', $ttl)),
        );

        $this->entityManager->persist($entity);
        $this->entityManager->flush();

        return ['token' => $raw, 'entity' => $entity];
    }

    /**
     * Spends a refresh token. Returns it on success; throws invalid_grant
     * otherwise — and revokes the family when the token was already spent.
     */
    public function rotate(string $raw, string $clientId): McpRefreshToken
    {
        $hash = hash('sha256', $raw);
        $token = '' === $raw ? null : $this->repository->findOneBy(['tokenHash' => $hash]);

        if (!$token instanceof McpRefreshToken || $token->isRevoked() || $token->isExpired()) {
            throw new OAuthException('invalid_grant', 'Refresh token is invalid, expired or revoked.');
        }
        if (!hash_equals($token->getClientId(), $clientId)) {
            throw new OAuthException('invalid_grant', 'Refresh token was issued to a different client.');
        }

        // Spent in one conditional UPDATE, for the same reason the
        // authorization code is: two requests with the same token must not
        // both win.
        $spent = $this->entityManager->createQuery(\sprintf(
            'UPDATE %s r SET r.usedAt = :now WHERE r.tokenHash = :hash AND r.usedAt IS NULL AND r.revoked = false',
            McpRefreshToken::class,
        ))->setParameter('now', new \DateTimeImmutable(), 'datetime_immutable')
            ->setParameter('hash', $hash)
            ->execute();

        if (1 !== $spent) {
            $this->revokeFamily($token->getFamily());
            $this->logger?->warning('MCP OAuth: refresh token reused, token family revoked', [
                'client_id' => $clientId,
                'admin_user_id' => $token->getAdminUserId(),
                'family_prefix' => substr($token->getFamily(), 0, 8),
            ]);

            throw new OAuthException('invalid_grant', 'Refresh token was already used. All tokens of this authorization are revoked; authorise again.');
        }

        $token->markUsed();

        return $token;
    }

    /** Revokes every refresh token and every access token of a family. */
    public function revokeFamily(string $family): void
    {
        $this->entityManager->createQuery(\sprintf('UPDATE %s r SET r.revoked = true WHERE r.family = :family', McpRefreshToken::class))
            ->setParameter('family', $family)
            ->execute();
        $this->entityManager->createQuery(\sprintf('UPDATE %s a SET a.revoked = true WHERE a.refreshFamily = :family', McpAccessToken::class))
            ->setParameter('family', $family)
            ->execute();
    }

    /** RFC 7009 for a refresh token: the family goes with it. No-op if unknown. */
    public function revokeRaw(string $raw): void
    {
        if (!str_starts_with($raw, self::PREFIX)) {
            return;
        }

        $token = $this->repository->findOneBy(['tokenHash' => hash('sha256', $raw)]);
        if ($token instanceof McpRefreshToken) {
            $this->revokeFamily($token->getFamily());
        }
    }
}
