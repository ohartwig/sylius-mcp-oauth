<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * A short-lived OAuth authorization code (RFC 6749 + PKCE RFC 7636). Issued by
 * /authorize once the admin user consents, exchanged at /token for an access
 * token. Only the SHA-256 hash of the raw code is stored. Single-use and
 * time-limited; bound to the client, redirect URI and the consenting admin user.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_mcp_authorization_code')]
/*
 * idx_mcp_code_admin exists in the database -- Version20260713130000 in
 * the consuming application created it -- but was never declared here, so
 * a schema check asks for it to be dropped. It is the index the cleanup
 * query for a revoked admin runs on; declaring it is the fix, dropping it
 * is not.
 */
#[ORM\Index(name: 'idx_mcp_code_admin', columns: ['admin_user_id'])]
/*
 * The unique index is declared here, under the name the migration created,
 * rather than as `unique: true` on the field. Doctrine derives a hashed
 * UNIQ_... name from that flag, so a schema check comparing the mapping
 * against a migrated database reports a RENAME INDEX for it on every run --
 * forever, with nothing actually wrong. Same uniqueness, named where it can be
 * read against the migration that wrote it.
 */
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_code_hash', columns: ['code_hash'])]
class McpAuthorizationCode
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(name: 'code_hash', type: 'string', length: 64)]
    private string $codeHash;

    #[ORM\Column(name: 'client_id', type: 'string', length: 64)]
    private string $clientId;

    #[ORM\Column(name: 'admin_user_id', type: 'integer')]
    private int $adminUserId;

    #[ORM\Column(name: 'redirect_uri', type: 'string', length: 512)]
    private string $redirectUri;

    /** @var list<string> */
    #[ORM\Column(type: 'json')]
    private array $scopes;

    #[ORM\Column(name: 'code_challenge', type: 'string', length: 191)]
    private string $codeChallenge;

    #[ORM\Column(name: 'code_challenge_method', type: 'string', length: 10)]
    private string $codeChallengeMethod;

    #[ORM\Column(name: 'expires_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'boolean')]
    private bool $used = false;

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /** RFC 8707 resource the authorization was requested for. */
    #[ORM\Column(type: 'string', length: 512, nullable: true)]
    private ?string $resource = null;

    /** @param list<string> $scopes */
    public function __construct(
        string $codeHash,
        string $clientId,
        int $adminUserId,
        string $redirectUri,
        array $scopes,
        string $codeChallenge,
        string $codeChallengeMethod,
        \DateTimeImmutable $expiresAt,
        ?string $resource = null,
    ) {
        $this->resource = $resource;
        $this->codeHash = $codeHash;
        $this->clientId = $clientId;
        $this->adminUserId = $adminUserId;
        $this->redirectUri = $redirectUri;
        $this->scopes = $scopes;
        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
        $this->expiresAt = $expiresAt;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getCodeHash(): string
    {
        return $this->codeHash;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getAdminUserId(): int
    {
        return $this->adminUserId;
    }

    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }

    /** @return list<string> */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getCodeChallenge(): string
    {
        return $this->codeChallenge;
    }

    public function getCodeChallengeMethod(): string
    {
        return $this->codeChallengeMethod;
    }

    public function getResource(): ?string
    {
        return $this->resource;
    }

    public function isUsable(?\DateTimeImmutable $now = null): bool
    {
        return !$this->used && $this->expiresAt > ($now ?? new \DateTimeImmutable());
    }

    public function markUsed(): void
    {
        $this->used = true;
    }
}
