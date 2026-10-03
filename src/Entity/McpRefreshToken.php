<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * A single-use refresh token (OAuth 2.1 §4.3.1, rotation for public clients).
 *
 * Every refresh replaces the token with a new one in the same family and
 * marks the old one used. A used token presented again means one of two
 * parties holding it is not the legitimate client — and the server cannot
 * tell which — so the whole family is revoked, access tokens included
 * ({@see \Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager}).
 *
 * Only the SHA-256 hash of the raw token is stored.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_mcp_refresh_token')]
#[ORM\Index(name: 'idx_mcp_refresh_family', columns: ['family'])]
#[ORM\Index(name: 'idx_mcp_refresh_admin', columns: ['admin_user_id'])]
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_refresh_hash', columns: ['token_hash'])]
class McpRefreshToken
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(name: 'token_hash', type: 'string', length: 64)]
    private string $tokenHash;

    #[ORM\Column(type: 'string', length: 64)]
    private string $family;

    #[ORM\Column(name: 'admin_user_id', type: 'integer')]
    private int $adminUserId;

    #[ORM\Column(name: 'client_id', type: 'string', length: 191)]
    private string $clientId;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    private array $scopes;

    #[ORM\Column(type: 'string', length: 512, nullable: true)]
    private ?string $audience;

    #[ORM\Column(name: 'expires_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(name: 'used_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $usedAt = null;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /** @param list<string> $scopes */
    public function __construct(
        string $tokenHash,
        string $family,
        int $adminUserId,
        string $clientId,
        array $scopes,
        ?string $audience,
        \DateTimeImmutable $expiresAt,
    ) {
        $this->tokenHash = $tokenHash;
        $this->family = $family;
        $this->adminUserId = $adminUserId;
        $this->clientId = $clientId;
        $this->scopes = $scopes;
        $this->audience = $audience;
        $this->expiresAt = $expiresAt;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getTokenHash(): string
    {
        return $this->tokenHash;
    }

    public function getFamily(): string
    {
        return $this->family;
    }

    public function getAdminUserId(): int
    {
        return $this->adminUserId;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    /** @return list<string> */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getAudience(): ?string
    {
        return $this->audience;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getUsedAt(): ?\DateTimeImmutable
    {
        return $this->usedAt;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function isExpired(?\DateTimeImmutable $now = null): bool
    {
        return $this->expiresAt <= ($now ?? new \DateTimeImmutable());
    }

    public function markUsed(?\DateTimeImmutable $now = null): void
    {
        $this->usedAt = $now ?? new \DateTimeImmutable();
    }

    public function revoke(): void
    {
        $this->revoked = true;
    }
}
