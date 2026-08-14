<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * A long-lived MCP access token bound to a single Sylius admin user, mirroring
 * the TYPO3 `tx_mcpserver_access_tokens` model. The raw token is shown to the
 * operator exactly once (at creation); only its SHA-256 hash is persisted, so a
 * DB leak does not expose usable tokens. A request to /_mcp authenticates by
 * presenting the raw token as `Authorization: Bearer <token>`; the security
 * layer resolves it back to the owning admin user.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_mcp_access_token')]
#[ORM\Index(name: 'idx_mcp_token_admin', columns: ['admin_user_id'])]
/*
 * The unique index is declared here, under the name the migration created,
 * rather than as `unique: true` on the field. Doctrine derives a hashed
 * UNIQ_... name from that flag, so a schema check comparing the mapping
 * against a migrated database reports a RENAME INDEX for it on every run --
 * forever, with nothing actually wrong. Same uniqueness, named where it can be
 * read against the migration that wrote it.
 */
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_token_hash', columns: ['token_hash'])]
class McpAccessToken
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    /** SHA-256 hex of the raw token. */
    #[ORM\Column(name: 'token_hash', type: 'string', length: 64)]
    private string $tokenHash;

    /** FK to sylius_admin_user.id (plain id, not an ORM association — loose coupling to the Sylius model). */
    #[ORM\Column(name: 'admin_user_id', type: 'integer')]
    private int $adminUserId;

    /** Human label, e.g. the OAuth client name or a manually chosen name. */
    #[ORM\Column(type: 'string', length: 191)]
    private string $name;

    /** OAuth client_id that obtained this token (null for CLI-minted tokens). */
    #[ORM\Column(name: 'client_id', type: 'string', length: 191, nullable: true)]
    private ?string $clientId = null;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    private array $scopes = ['mcp'];

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(name: 'last_used_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    /** null = never expires. */
    #[ORM\Column(name: 'expires_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /** @param list<string> $scopes */
    public function __construct(
        string $tokenHash,
        int $adminUserId,
        string $name,
        array $scopes = ['mcp'],
        ?\DateTimeImmutable $expiresAt = null,
        ?string $clientId = null,
    ) {
        $this->tokenHash = $tokenHash;
        $this->adminUserId = $adminUserId;
        $this->name = $name;
        $this->scopes = $scopes;
        $this->expiresAt = $expiresAt;
        $this->clientId = $clientId;
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

    public function getAdminUserId(): int
    {
        return $this->adminUserId;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    /** @return list<string> */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function touch(?\DateTimeImmutable $now = null): void
    {
        $this->lastUsedAt = $now ?? new \DateTimeImmutable();
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function revoke(): void
    {
        $this->revoked = true;
    }

    public function isValid(?\DateTimeImmutable $now = null): bool
    {
        if ($this->revoked) {
            return false;
        }

        if ($this->expiresAt !== null && $this->expiresAt <= ($now ?? new \DateTimeImmutable())) {
            return false;
        }

        return true;
    }
}
