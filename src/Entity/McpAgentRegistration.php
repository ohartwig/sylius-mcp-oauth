<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * An agent identity registered through the auth.md identity endpoint
 * (`anonymous` or `service_auth`), and the state of its claim ceremony.
 *
 * Until an administrator claims it, the identity carries no administrator and
 * therefore cannot obtain an MCP access token: tokens are always bound to an
 * administrator ({@see McpAccessToken}). Claiming fills `adminUserId` and
 * `scopes`.
 *
 * Every secret is stored as a SHA-256 hash: the claim token the agent holds,
 * the claim-attempt token in the verification URI and the user code.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_mcp_agent_registration')]
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_agent_reg_id', columns: ['registration_id'])]
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_agent_reg_claim', columns: ['claim_token_hash'])]
#[ORM\Index(name: 'idx_mcp_agent_reg_attempt', columns: ['attempt_token_hash'])]
class McpAgentRegistration
{
    public const TYPE_ANONYMOUS = 'anonymous';
    public const TYPE_SERVICE_AUTH = 'service_auth';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    /** Public identifier, `reg_<hex>`; the `sub` of the identity assertions. */
    #[ORM\Column(name: 'registration_id', type: 'string', length: 64)]
    private string $registrationId;

    #[ORM\Column(type: 'string', length: 20)]
    private string $type;

    #[ORM\Column(name: 'claim_token_hash', type: 'string', length: 64)]
    private string $claimTokenHash;

    /** End of the outer claim window. */
    #[ORM\Column(name: 'claim_expires_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $claimExpiresAt;

    /** The account the ceremony is bound to (login_hint, or the email given at /claim). */
    #[ORM\Column(name: 'claim_email', type: 'string', length: 191, nullable: true)]
    private ?string $claimEmail = null;

    #[ORM\Column(name: 'attempt_id', type: 'string', length: 64, nullable: true)]
    private ?string $attemptId = null;

    #[ORM\Column(name: 'attempt_token_hash', type: 'string', length: 64, nullable: true)]
    private ?string $attemptTokenHash = null;

    #[ORM\Column(name: 'user_code_hash', type: 'string', length: 64, nullable: true)]
    private ?string $userCodeHash = null;

    #[ORM\Column(name: 'user_code_expires_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $userCodeExpiresAt = null;

    #[ORM\Column(name: 'failed_code_attempts', type: 'integer')]
    private int $failedCodeAttempts = 0;

    #[ORM\Column(name: 'last_polled_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastPolledAt = null;

    /** The administrator who claimed the identity; null while unclaimed. */
    #[ORM\Column(name: 'admin_user_id', type: 'integer', nullable: true)]
    private ?int $adminUserId = null;

    /** @var list<string> scopes granted at the claim */
    #[ORM\Column(type: 'json')]
    private array $scopes = [];

    #[ORM\Column(name: 'claimed_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $claimedAt = null;

    /** When the claim grant handed out its token; the claim token is spent from then on. */
    #[ORM\Column(name: 'claim_redeemed_at', type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $claimRedeemedAt = null;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(name: 'created_ip', type: 'string', length: 45, nullable: true)]
    private ?string $createdIp = null;

    public function __construct(
        string $registrationId,
        string $type,
        string $claimTokenHash,
        \DateTimeImmutable $claimExpiresAt,
        \DateTimeImmutable $createdAt,
        ?string $claimEmail = null,
        ?string $createdIp = null,
    ) {
        $this->registrationId = $registrationId;
        $this->type = $type;
        $this->claimTokenHash = $claimTokenHash;
        $this->claimExpiresAt = $claimExpiresAt;
        $this->createdAt = $createdAt;
        $this->claimEmail = $claimEmail;
        $this->createdIp = $createdIp;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getRegistrationId(): string
    {
        return $this->registrationId;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getClaimTokenHash(): string
    {
        return $this->claimTokenHash;
    }

    public function getClaimExpiresAt(): \DateTimeImmutable
    {
        return $this->claimExpiresAt;
    }

    public function getClaimEmail(): ?string
    {
        return $this->claimEmail;
    }

    public function getAttemptId(): ?string
    {
        return $this->attemptId;
    }

    public function getAttemptTokenHash(): ?string
    {
        return $this->attemptTokenHash;
    }

    public function getUserCodeHash(): ?string
    {
        return $this->userCodeHash;
    }

    public function getUserCodeExpiresAt(): ?\DateTimeImmutable
    {
        return $this->userCodeExpiresAt;
    }

    public function getFailedCodeAttempts(): int
    {
        return $this->failedCodeAttempts;
    }

    public function getLastPolledAt(): ?\DateTimeImmutable
    {
        return $this->lastPolledAt;
    }

    public function getAdminUserId(): ?int
    {
        return $this->adminUserId;
    }

    /** @return list<string> */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getClaimedAt(): ?\DateTimeImmutable
    {
        return $this->claimedAt;
    }

    public function getClaimRedeemedAt(): ?\DateTimeImmutable
    {
        return $this->claimRedeemedAt;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getCreatedIp(): ?string
    {
        return $this->createdIp;
    }

    public function isClaimed(): bool
    {
        return null !== $this->adminUserId;
    }

    public function bindEmail(string $email): void
    {
        $this->claimEmail = $email;
    }

    /** Starts a claim attempt; a previous attempt and its code stop working. */
    public function startAttempt(string $attemptId, string $attemptTokenHash, string $userCodeHash, \DateTimeImmutable $expiresAt): void
    {
        $this->attemptId = $attemptId;
        $this->attemptTokenHash = $attemptTokenHash;
        $this->userCodeHash = $userCodeHash;
        $this->userCodeExpiresAt = $expiresAt;
        $this->failedCodeAttempts = 0;
    }

    /** @return int the number of failed attempts so far */
    public function recordFailedCode(): int
    {
        return ++$this->failedCodeAttempts;
    }

    /** Ends the current attempt: its verification URI and code are spent. */
    public function endAttempt(): void
    {
        $this->attemptTokenHash = null;
        $this->userCodeHash = null;
    }

    /** @param list<string> $scopes */
    public function claim(int $adminUserId, array $scopes, \DateTimeImmutable $at): void
    {
        $this->adminUserId = $adminUserId;
        $this->scopes = $scopes;
        $this->claimedAt = $at;
        $this->endAttempt();
    }

    public function markPolled(\DateTimeImmutable $at): void
    {
        $this->lastPolledAt = $at;
    }

    public function redeemClaim(\DateTimeImmutable $at): void
    {
        $this->claimRedeemedAt = $at;
    }

    public function revoke(): void
    {
        $this->revoked = true;
        $this->endAttempt();
    }
}
