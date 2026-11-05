<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Koh\SyliusMcpOAuth\Entity\McpAgentRegistration;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;

/**
 * The auth.md v0.6.0 registration and claim ceremony (AUTH.md Steps 3–5).
 *
 * An agent registers `anonymous` (no user behind it) or `service_auth` (it
 * names the user by email). Neither gets anything on its own: this server
 * hands MCP access only to an administrator, so `pre_claim_scopes` is empty
 * and an unclaimed identity can never be exchanged for an access token. The
 * only way in is the claim: an administrator signs in to the admin, opens the
 * verification URI and types the six-digit code the agent showed them. Only
 * then does the claim grant, polled by the agent, return an access token —
 * once — and a service-signed identity assertion to mint further ones with.
 *
 * Every window is short: the claim window (default one hour), the user code
 * (ten minutes, five wrong guesses end the attempt), and the post-claim
 * assertion (default one day). Claim tokens, attempt tokens and user codes are
 * stored hashed and each is spent on use.
 */
final class AgentRegistrationManager
{
    public const USER_CODE_TTL = 600;
    public const POLL_INTERVAL = 5;
    public const MAX_CODE_ATTEMPTS = 5;

    public const RESULT_CLAIMED = 'claimed';
    public const RESULT_WRONG_CODE = 'wrong_code';
    public const RESULT_LOCKED = 'locked';
    public const RESULT_EXPIRED = 'expired';
    public const RESULT_WRONG_ACCOUNT = 'wrong_account';

    /** @var EntityRepository<McpAgentRegistration> */
    private readonly EntityRepository $repository;

    /** @var \Closure(): \DateTimeImmutable */
    private readonly \Closure $clock;

    /**
     * @param list<string>                         $postClaimScopes scopes an administrator grants by claiming
     * @param (\Closure(): \DateTimeImmutable)|null $clock
     */
    public function __construct(
        private readonly EntityManagerInterface $entityManager,
        private readonly IdentityAssertionSigner $signer,
        private readonly array $postClaimScopes = ['mcp'],
        private readonly int $claimTtl = 3600,
        private readonly int $assertionTtl = 86400,
        ?\Closure $clock = null,
    ) {
        $this->repository = $entityManager->getRepository(McpAgentRegistration::class);
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    /**
     * POST identity_endpoint. Returns the registration response body.
     *
     * @return array<string, mixed>
     *
     * @throws AgentAuthException
     */
    public function register(string $type, ?string $loginHint, ?string $ip, string $issuer, string $claimUrl, string $verificationBase): array
    {
        $email = null;
        if (McpAgentRegistration::TYPE_SERVICE_AUTH === $type) {
            $email = self::normaliseEmail($loginHint);
            if (null === $email) {
                throw new AgentAuthException('invalid_login_hint', 'login_hint must be an email address.');
            }
        } elseif (McpAgentRegistration::TYPE_ANONYMOUS !== $type) {
            throw match ($type) {
                'identity_assertion' => new AgentAuthException('issuer_not_enabled', 'This service trusts no identity provider; register as anonymous or service_auth.'),
                default => new AgentAuthException('invalid_request', 'type must be one of anonymous, service_auth.'),
            };
        }

        $now = $this->now();
        $claimToken = 'clm_'.bin2hex(random_bytes(32));
        $registration = new McpAgentRegistration(
            registrationId: 'reg_'.bin2hex(random_bytes(16)),
            type: $type,
            claimTokenHash: self::hash($claimToken),
            claimExpiresAt: $now->modify(\sprintf('+%d seconds', $this->claimTtl)),
            createdAt: $now,
            claimEmail: $email,
            createdIp: $ip,
        );

        $body = [
            'registration_id' => $registration->getRegistrationId(),
            'registration_type' => $type,
        ];

        $ceremony = null;
        if (McpAgentRegistration::TYPE_ANONYMOUS === $type) {
            // The pre-claim assertion exists because the profile says it does;
            // it lives as long as the claim window and exchanges for nothing.
            $body['identity_assertion'] = $this->signer->sign($this->claims($registration, $issuer, false, $registration->getClaimExpiresAt()));
            $body['assertion_expires'] = self::format($registration->getClaimExpiresAt());
            $body['pre_claim_scopes'] = [];
        } else {
            $ceremony = $this->startAttempt($registration, $verificationBase);
        }

        $this->entityManager->persist($registration);
        $this->entityManager->flush();

        $body += [
            'claim_url' => $claimUrl,
            'claim_token' => $claimToken,
            'claim_token_expires' => self::format($registration->getClaimExpiresAt()),
            'post_claim_scopes' => $this->postClaimScopes,
        ];
        if (null !== $ceremony) {
            $body['claim'] = $ceremony;
        }

        return $body;
    }

    /**
     * POST claim_endpoint: a fresh claim attempt (user code and verification
     * URI). Any earlier attempt of the registration stops working.
     *
     * @return array<string, mixed>
     *
     * @throws AgentAuthException
     */
    public function initiateClaim(string $claimToken, ?string $email, string $verificationBase): array
    {
        $registration = $this->byClaimToken($claimToken);
        if (null === $registration) {
            throw new AgentAuthException('invalid_claim_token', 'claim_token is unknown.');
        }
        if ($registration->isRevoked() || $registration->getClaimExpiresAt() <= $this->now()) {
            throw new AgentAuthException('claim_expired', 'The registration expired before it was claimed; register again.', 410);
        }
        if ($registration->isClaimed()) {
            throw new AgentAuthException('claimed_or_in_flight', 'This registration has already been claimed.', 409);
        }

        if (null !== $email && '' !== $email) {
            $normalised = self::normaliseEmail($email);
            if (null === $normalised) {
                throw new AgentAuthException('invalid_request', 'email must be an email address.');
            }
            $bound = $registration->getClaimEmail();
            if (null !== $bound && $bound !== $normalised) {
                throw new AgentAuthException('invalid_request', 'email does not match the account this registration is bound to.');
            }
            $registration->bindEmail($normalised);
        }

        $attempt = $this->startAttempt($registration, $verificationBase);
        $this->entityManager->flush();

        return [
            'registration_id' => $registration->getRegistrationId(),
            'claim_attempt_id' => (string) $registration->getAttemptId(),
            'status' => 'initiated',
            'expires_at' => self::format($registration->getClaimExpiresAt()),
            'claim_attempt' => $attempt,
        ];
    }

    /** The registration a verification URI points at, while its attempt can still be confirmed. */
    public function findOpenAttempt(string $attemptToken): ?McpAgentRegistration
    {
        if ('' === $attemptToken) {
            return null;
        }

        $registration = $this->repository->findOneBy(['attemptTokenHash' => self::hash($attemptToken)]);
        if (!$registration instanceof McpAgentRegistration || $registration->isRevoked() || $registration->isClaimed()) {
            return null;
        }

        return $registration;
    }

    /**
     * The signed-in administrator confirms the user code.
     *
     * @return self::RESULT_*
     */
    public function confirm(McpAgentRegistration $registration, int $adminUserId, string $adminEmail, string $userCode): string
    {
        $now = $this->now();
        $codeExpires = $registration->getUserCodeExpiresAt();
        if (null === $registration->getUserCodeHash() || null === $codeExpires || $codeExpires <= $now || $registration->getClaimExpiresAt() <= $now) {
            return self::RESULT_EXPIRED;
        }

        $bound = $registration->getClaimEmail();
        if (null !== $bound && $bound !== self::normaliseEmail($adminEmail)) {
            return self::RESULT_WRONG_ACCOUNT;
        }

        $code = preg_replace('/\s+/', '', $userCode) ?? '';
        if (!hash_equals($registration->getUserCodeHash(), self::codeHash($registration, $code))) {
            $failed = $registration->recordFailedCode();
            if ($failed >= self::MAX_CODE_ATTEMPTS) {
                $registration->endAttempt();
                $this->entityManager->flush();

                return self::RESULT_LOCKED;
            }
            $this->entityManager->flush();

            return self::RESULT_WRONG_CODE;
        }

        $registration->claim($adminUserId, $this->postClaimScopes, $now);
        $this->entityManager->flush();

        return self::RESULT_CLAIMED;
    }

    /**
     * The claim grant (`urn:workos:agent-auth:grant-type:claim`). Returns the
     * claimed registration exactly once; the caller mints the access token.
     *
     * @throws OAuthException authorization_pending, slow_down, expired_token or invalid_grant
     */
    public function redeemClaim(string $claimToken): McpAgentRegistration
    {
        $registration = $this->byClaimToken($claimToken);
        if (null === $registration || $registration->isRevoked() || null !== $registration->getClaimRedeemedAt()) {
            throw new OAuthException('invalid_grant', 'claim_token is unknown, revoked or already redeemed.');
        }

        $now = $this->now();
        if ($registration->getClaimExpiresAt() <= $now) {
            throw new OAuthException('expired_token', 'The claim window has closed; register again.');
        }
        if (!$registration->isClaimed()) {
            $codeExpires = $registration->getUserCodeExpiresAt();
            if (null !== $codeExpires && $codeExpires <= $now) {
                throw new OAuthException('expired_token', 'The user code expired; start a new claim attempt at the claim endpoint.');
            }
            $last = $registration->getLastPolledAt();
            $registration->markPolled($now);
            $this->entityManager->flush();
            if (null !== $last && $now->getTimestamp() - $last->getTimestamp() < self::POLL_INTERVAL) {
                throw new OAuthException('slow_down', \sprintf('Poll at most every %d seconds.', self::POLL_INTERVAL));
            }

            throw new OAuthException('authorization_pending', 'No administrator has confirmed the user code yet.');
        }

        // Spend the claim token in one conditional UPDATE: two polls arriving
        // together must not both receive a token.
        $redeemed = $this->entityManager->createQuery(\sprintf(
            'UPDATE %s r SET r.claimRedeemedAt = :now WHERE r.id = :id AND r.claimRedeemedAt IS NULL',
            McpAgentRegistration::class,
        ))->setParameter('now', $now, 'datetime_immutable')->setParameter('id', $registration->getId())->execute();
        if (1 !== $redeemed) {
            throw new OAuthException('invalid_grant', 'claim_token has already been redeemed.');
        }
        $registration->redeemClaim($now);

        return $registration;
    }

    /**
     * The RFC 7523 jwt-bearer grant: a claimed registration for a valid
     * post-claim assertion.
     *
     * @throws OAuthException
     */
    public function exchange(string $assertion): McpAgentRegistration
    {
        $claims = $this->signer->verify($assertion);
        $subject = $claims['sub'] ?? null;
        $expires = $claims['exp'] ?? null;
        if (null === $claims || !\is_string($subject) || !\is_int($expires) || $expires <= $this->now()->getTimestamp()) {
            throw new OAuthException('invalid_grant', 'The identity assertion is invalid or expired.');
        }

        $registration = $this->repository->findOneBy(['registrationId' => $subject]);
        if (!$registration instanceof McpAgentRegistration || $registration->isRevoked()) {
            throw new OAuthException('invalid_grant', 'The registration of this assertion is revoked or unknown.');
        }

        if (true !== ($claims['claimed'] ?? null)) {
            if ($registration->isClaimed()) {
                throw new OAuthException('invalid_grant', 'This pre-claim assertion was superseded by the one the claim grant returned.');
            }

            throw new OAuthException('invalid_scope', 'pre_claim_scopes is empty: this identity has no access until an administrator claims it (claim ceremony, AUTH.md Step 4).');
        }

        if (!$registration->isClaimed()) {
            throw new OAuthException('invalid_grant', 'The registration of this assertion is not claimed.');
        }

        return $registration;
    }

    /**
     * A post-claim identity assertion for a claimed registration.
     *
     * @return array{assertion: string, expires: string}
     */
    public function postClaimAssertion(McpAgentRegistration $registration, string $issuer): array
    {
        $expires = $this->now()->modify(\sprintf('+%d seconds', $this->assertionTtl));

        return [
            'assertion' => $this->signer->sign($this->claims($registration, $issuer, true, $expires)),
            'expires' => self::format($expires),
        ];
    }

    /** @return list<string> */
    public function getPostClaimScopes(): array
    {
        return $this->postClaimScopes;
    }

    /** Ends a registration: its assertions stop exchanging and its ceremony stops. */
    public function revoke(string $registrationId): void
    {
        $registration = $this->repository->findOneBy(['registrationId' => $registrationId]);
        if ($registration instanceof McpAgentRegistration && !$registration->isRevoked()) {
            $registration->revoke();
            $this->entityManager->flush();
        }
    }

    /** @return array{user_code: string, expires_in: int, verification_uri: string, interval: int} */
    private function startAttempt(McpAgentRegistration $registration, string $verificationBase): array
    {
        $attemptToken = bin2hex(random_bytes(32));
        $userCode = \sprintf('%06d', random_int(0, 999999));
        $registration->startAttempt(
            'cla_'.bin2hex(random_bytes(16)),
            self::hash($attemptToken),
            self::codeHash($registration, $userCode),
            $this->now()->modify(\sprintf('+%d seconds', self::USER_CODE_TTL)),
        );

        return [
            'user_code' => $userCode,
            'expires_in' => self::USER_CODE_TTL,
            'verification_uri' => $verificationBase.(str_contains($verificationBase, '?') ? '&' : '?').http_build_query(['claim_attempt_token' => $attemptToken]),
            'interval' => self::POLL_INTERVAL,
        ];
    }

    /** @return array<string, scalar> */
    private function claims(McpAgentRegistration $registration, string $issuer, bool $claimed, \DateTimeImmutable $expires): array
    {
        $now = $this->now();

        return [
            'iss' => $issuer,
            'sub' => $registration->getRegistrationId(),
            'aud' => $issuer,
            'iat' => $now->getTimestamp(),
            'exp' => $expires->getTimestamp(),
            'jti' => bin2hex(random_bytes(16)),
            'registration_type' => $registration->getType(),
            'claimed' => $claimed,
        ];
    }

    private function byClaimToken(string $claimToken): ?McpAgentRegistration
    {
        if ('' === $claimToken) {
            return null;
        }

        $registration = $this->repository->findOneBy(['claimTokenHash' => self::hash($claimToken)]);

        return $registration instanceof McpAgentRegistration ? $registration : null;
    }

    private function now(): \DateTimeImmutable
    {
        return ($this->clock)();
    }

    private static function normaliseEmail(?string $email): ?string
    {
        $email = mb_strtolower(trim((string) $email));

        return false !== filter_var($email, \FILTER_VALIDATE_EMAIL) && mb_strlen($email) <= 191 ? $email : null;
    }

    private static function hash(string $secret): string
    {
        return hash('sha256', $secret);
    }

    private static function codeHash(McpAgentRegistration $registration, string $code): string
    {
        return hash('sha256', $registration->getRegistrationId().':'.$code);
    }

    private static function format(\DateTimeImmutable $at): string
    {
        return $at->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.v\Z');
    }
}
