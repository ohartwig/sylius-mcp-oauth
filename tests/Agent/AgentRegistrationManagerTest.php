<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Agent;

use Koh\SyliusMcpOAuth\Agent\AgentAuthException;
use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
use Koh\SyliusMcpOAuth\Agent\IdentityAssertionSigner;
use Koh\SyliusMcpOAuth\Entity\McpAgentRegistration;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * The auth.md registration and claim ceremony. The property that matters
 * most: nothing an agent can do on its own yields an MCP token. Only an
 * administrator typing the user code turns a registration into one that can.
 */
#[CoversClass(AgentRegistrationManager::class)]
#[CoversClass(McpAgentRegistration::class)]
#[CoversClass(AgentAuthException::class)]
final class AgentRegistrationManagerTest extends TestCase
{
    private const ISSUER = 'https://shop.example';
    private const CLAIM_URL = 'https://shop.example/mcp/oauth/agent/identity/claim';
    private const VERIFY = 'https://shop.example/admin/mcp/claim';

    private RegistrationStore $store;

    private \DateTimeImmutable $now;

    private IdentityAssertionSigner $signer;

    protected function setUp(): void
    {
        $this->store = new RegistrationStore();
        $this->now = new \DateTimeImmutable('2026-11-05 12:00:00', new \DateTimeZone('UTC'));
        $this->signer = new IdentityAssertionSigner('test-secret');
    }

    public function testAnAnonymousRegistrationHasTheAuthMdShapeAndGrantsNothingBeforeTheClaim(): void
    {
        $body = $this->anonymous();

        self::assertSame([
            'registration_id', 'registration_type', 'identity_assertion', 'assertion_expires', 'pre_claim_scopes',
            'claim_url', 'claim_token', 'claim_token_expires', 'post_claim_scopes',
        ], array_keys($body));
        self::assertMatchesRegularExpression('/^reg_[0-9a-f]{32}$/', $body['registration_id']);
        self::assertSame('anonymous', $body['registration_type']);
        self::assertSame([], $body['pre_claim_scopes']);
        self::assertSame(['mcp:read'], $body['post_claim_scopes']);
        self::assertSame(self::CLAIM_URL, $body['claim_url']);
        self::assertMatchesRegularExpression('/^clm_[0-9a-f]{64}$/', $body['claim_token']);
        self::assertSame('2026-11-05T13:00:00.000Z', $body['claim_token_expires']);
        self::assertSame('2026-11-05T13:00:00.000Z', $body['assertion_expires']);

        $claims = $this->signer->verify($body['identity_assertion']);
        self::assertNotNull($claims);
        self::assertSame($body['registration_id'], $claims['sub']);
        self::assertSame(self::ISSUER, $claims['iss']);
        self::assertSame(self::ISSUER, $claims['aud']);
        self::assertFalse($claims['claimed']);
        self::assertSame('anonymous', $claims['registration_type']);
        self::assertSame($this->now->getTimestamp(), $claims['iat']);
        self::assertSame($this->now->getTimestamp() + 3600, $claims['exp']);

        $row = $this->store->rows[0];
        self::assertSame('192.0.2.1', $row->getCreatedIp());
        self::assertSame(hash('sha256', $body['claim_token']), $row->getClaimTokenHash());
        self::assertFalse($row->isClaimed());
        self::assertNull($row->getAttemptId());
        self::assertSame(1, $this->store->flushes);
        self::assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $claims['jti']);
    }

    public function testTheDefaultsAreAnHourToClaimADayPerAssertionAndTheMcpScope(): void
    {
        $manager = new AgentRegistrationManager($this->store->entityManager($this), $this->signer, clock: fn (): \DateTimeImmutable => $this->now);
        $body = $manager->register('anonymous', null, null, self::ISSUER, self::CLAIM_URL, self::VERIFY);

        self::assertSame('2026-11-05T13:00:00.000Z', $body['claim_token_expires']);
        self::assertSame(['mcp'], $body['post_claim_scopes']);
        $attempt = $manager->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $manager->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);
        $manager->confirm($registration, 7, 'a@b.example', $attempt['user_code']);
        self::assertSame('2026-11-06T12:00:00.000Z', $manager->postClaimAssertion($manager->redeemClaim($body['claim_token']), self::ISSUER)['expires']);
    }

    /** The code is stored salted with the registration, never in clear. */
    public function testTheUserCodeIsStoredAsASaltedHash(): void
    {
        $body = $this->anonymous();
        $code = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt']['user_code'];

        self::assertSame(hash('sha256', $body['registration_id'].':'.$code), $this->store->rows[0]->getUserCodeHash());
    }

    /** Each step that changes state writes it. */
    public function testEveryStateChangeIsFlushed(): void
    {
        $body = $this->anonymous();
        $flushes = $this->store->flushes;
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        self::assertSame(++$flushes, $this->store->flushes);
        $this->expectOAuthError('authorization_pending', fn () => $this->manager()->redeemClaim($body['claim_token']));
        self::assertSame(++$flushes, $this->store->flushes);
        $registration = $this->store->rows[0];
        $wrong = '000000' === $attempt['user_code'] ? '111111' : '000000';
        $this->manager()->confirm($registration, 7, 'a@b.example', $wrong);
        self::assertSame(++$flushes, $this->store->flushes);
        for ($i = 2; $i <= AgentRegistrationManager::MAX_CODE_ATTEMPTS; ++$i) {
            $this->manager()->confirm($registration, 7, 'a@b.example', $wrong);
        }
        self::assertSame($flushes + 4, $this->store->flushes);
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $flushes = $this->store->flushes;
        $this->manager()->confirm($registration, 7, 'a@b.example', $attempt['user_code']);
        self::assertSame($flushes + 1, $this->store->flushes);
    }

    public function testAnAnonymousRegistrationRefusesAMalformedEmail(): void
    {
        $body = $this->anonymous();

        $this->expectAgentError('invalid_request', 400, fn () => $this->manager()->initiateClaim($body['claim_token'], 'nonsense', self::VERIFY));
        self::assertNull($this->store->rows[0]->getClaimEmail());
        self::assertNull($this->store->rows[0]->getAttemptId());
    }

    public function testAnEmailOfTheMaximumLengthIsAccepted(): void
    {
        $email = str_repeat('a', 64).'@'.str_repeat('b', 63).'.'.str_repeat('c', 54).'.example';
        self::assertSame(191, \strlen($email));

        $body = $this->manager()->register('service_auth', $email, null, self::ISSUER, self::CLAIM_URL, self::VERIFY);

        self::assertSame($email, $this->store->rows[0]->getClaimEmail());
        $this->expectAgentError('invalid_login_hint', 400, fn () => $this->manager()->register('service_auth', 'a'.$email, null, self::ISSUER, self::CLAIM_URL, self::VERIFY));
        self::assertSame('service_auth', $body['registration_type']);
    }

    public function testTheExceptionCarriesItsDescription(): void
    {
        $e = new AgentAuthException('x', 'described', 418);

        self::assertSame('described', $e->getMessage());
        self::assertSame(418, $e->status);
    }

    /** The pre-claim assertion exchanges for nothing — invalid_scope, not a token. */
    public function testAnUnclaimedAssertionCannotBeExchanged(): void
    {
        $body = $this->anonymous();

        $this->expectOAuthError('invalid_scope', fn () => $this->manager()->exchange($body['identity_assertion']));
    }

    public function testServiceAuthNeedsAnEmailAndStartsTheCeremonyAtOnce(): void
    {
        $body = $this->manager()->register('service_auth', ' Admin@Shop.Example ', null, self::ISSUER, self::CLAIM_URL, self::VERIFY);

        self::assertSame('service_auth', $body['registration_type']);
        self::assertArrayNotHasKey('identity_assertion', $body);
        self::assertArrayNotHasKey('pre_claim_scopes', $body);
        self::assertSame(['user_code', 'expires_in', 'verification_uri', 'interval'], array_keys($body['claim']));
        self::assertMatchesRegularExpression('/^\d{6}$/', $body['claim']['user_code']);
        self::assertSame(600, $body['claim']['expires_in']);
        self::assertSame(5, $body['claim']['interval']);
        self::assertMatchesRegularExpression('#^https://shop\.example/admin/mcp/claim\?claim_attempt_token=[0-9a-f]{64}$#', $body['claim']['verification_uri']);
        self::assertSame('admin@shop.example', $this->store->rows[0]->getClaimEmail());
        self::assertSame($this->store->rows[0], $this->manager()->findOpenAttempt($this->attemptToken($body['claim']['verification_uri'])));
    }

    public function testAVerificationUriWithAQueryKeepsIt(): void
    {
        $body = $this->manager()->register('service_auth', 'a@b.example', null, self::ISSUER, self::CLAIM_URL, self::VERIFY.'?_locale=de');

        self::assertStringStartsWith(self::VERIFY.'?_locale=de&claim_attempt_token=', $body['claim']['verification_uri']);
    }

    /** @return iterable<string, array{string, ?string, string}> */
    public static function refusedRegistrations(): iterable
    {
        yield 'service_auth without login_hint' => ['service_auth', null, 'invalid_login_hint'];
        yield 'service_auth with a non-email' => ['service_auth', 'not an email', 'invalid_login_hint'];
        yield 'no trusted ID-JAG issuer' => ['identity_assertion', null, 'issuer_not_enabled'];
        yield 'unknown type' => ['password', null, 'invalid_request'];
        yield 'missing type' => ['', null, 'invalid_request'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('refusedRegistrations')]
    public function testRefusedRegistrationsPersistNothing(string $type, ?string $hint, string $error): void
    {
        try {
            $this->manager()->register($type, $hint, null, self::ISSUER, self::CLAIM_URL, self::VERIFY);
            self::fail('Expected an AgentAuthException.');
        } catch (AgentAuthException $e) {
            self::assertSame($error, $e->error);
            self::assertSame(400, $e->status);
        }

        self::assertSame([], $this->store->rows);
    }

    public function testInitiatingAClaimReturnsTheAttemptAndBindsTheEmail(): void
    {
        $body = $this->anonymous();

        $claim = $this->manager()->initiateClaim($body['claim_token'], 'Owner@Shop.Example', self::VERIFY);

        self::assertSame($body['registration_id'], $claim['registration_id']);
        self::assertMatchesRegularExpression('/^cla_[0-9a-f]{32}$/', $claim['claim_attempt_id']);
        self::assertSame('initiated', $claim['status']);
        self::assertSame('2026-11-05T13:00:00.000Z', $claim['expires_at']);
        self::assertSame(['user_code', 'expires_in', 'verification_uri', 'interval'], array_keys($claim['claim_attempt']));
        self::assertSame('owner@shop.example', $this->store->rows[0]->getClaimEmail());
    }

    /** A new attempt replaces the old one: its link and code stop working. */
    public function testANewAttemptRetiresThePreviousOne(): void
    {
        $body = $this->anonymous();
        $first = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY);
        $second = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY);

        self::assertNull($this->manager()->findOpenAttempt($this->attemptToken($first['claim_attempt']['verification_uri'])));
        self::assertNotNull($this->manager()->findOpenAttempt($this->attemptToken($second['claim_attempt']['verification_uri'])));
        self::assertNotSame($first['claim_attempt_id'], $second['claim_attempt_id']);
        self::assertNull($this->store->rows[0]->getClaimEmail());
    }

    public function testInitiatingAClaimIsRefusedForAnUnknownToken(): void
    {
        $this->anonymous();

        $this->expectAgentError('invalid_claim_token', 400, fn () => $this->manager()->initiateClaim('clm_nope', null, self::VERIFY));
        $this->expectAgentError('invalid_claim_token', 400, fn () => $this->manager()->initiateClaim('', null, self::VERIFY));
    }

    public function testInitiatingAClaimAfterTheWindowIsGone(): void
    {
        $body = $this->anonymous();
        $this->now = $this->now->modify('+3600 seconds');

        $this->expectAgentError('claim_expired', 410, fn () => $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY));
    }

    public function testInitiatingAClaimOfARevokedRegistration(): void
    {
        $body = $this->anonymous();
        $this->manager()->revoke($body['registration_id']);

        $this->expectAgentError('claim_expired', 410, fn () => $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY));
    }

    public function testInitiatingAClaimOfAClaimedRegistration(): void
    {
        $body = $this->claimed();

        $this->expectAgentError('claimed_or_in_flight', 409, fn () => $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY));
    }

    public function testTheEmailOfAServiceAuthRegistrationCannotBeSwapped(): void
    {
        $body = $this->manager()->register('service_auth', 'owner@shop.example', null, self::ISSUER, self::CLAIM_URL, self::VERIFY);

        $this->expectAgentError('invalid_request', 400, fn () => $this->manager()->initiateClaim($body['claim_token'], 'attacker@evil.example', self::VERIFY));
        $this->expectAgentError('invalid_request', 400, fn () => $this->manager()->initiateClaim($body['claim_token'], 'nonsense', self::VERIFY));

        $again = $this->manager()->initiateClaim($body['claim_token'], 'OWNER@shop.example', self::VERIFY);
        self::assertSame('initiated', $again['status']);
    }

    public function testTheRightCodeClaimsWithTheConfiguredScopes(): void
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);

        $result = $this->manager()->confirm($registration, 7, 'admin@shop.example', substr($attempt['user_code'], 0, 3).' '.substr($attempt['user_code'], 3));

        self::assertSame(AgentRegistrationManager::RESULT_CLAIMED, $result);
        self::assertSame(7, $registration->getAdminUserId());
        self::assertSame(['mcp:read'], $registration->getScopes());
        self::assertEquals($this->now, $registration->getClaimedAt());
        // The link is spent.
        self::assertNull($this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri'])));
    }

    public function testFiveWrongCodesEndTheAttempt(): void
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);
        $wrong = '000000' === $attempt['user_code'] ? '111111' : '000000';

        for ($i = 1; $i < AgentRegistrationManager::MAX_CODE_ATTEMPTS; ++$i) {
            self::assertSame(AgentRegistrationManager::RESULT_WRONG_CODE, $this->manager()->confirm($registration, 7, 'a@b.example', $wrong));
            self::assertSame($i, $registration->getFailedCodeAttempts());
        }
        self::assertSame(AgentRegistrationManager::RESULT_LOCKED, $this->manager()->confirm($registration, 7, 'a@b.example', $wrong));
        // Even the right code is useless now.
        self::assertSame(AgentRegistrationManager::RESULT_EXPIRED, $this->manager()->confirm($registration, 7, 'a@b.example', $attempt['user_code']));
        self::assertFalse($registration->isClaimed());
        self::assertNull($this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri'])));
    }

    public function testAnExpiredCodeDoesNotClaim(): void
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);
        $this->now = $this->now->modify('+600 seconds');

        self::assertSame(AgentRegistrationManager::RESULT_EXPIRED, $this->manager()->confirm($registration, 7, 'a@b.example', $attempt['user_code']));
        self::assertFalse($registration->isClaimed());
    }

    public function testACodeOutlivingTheClaimWindowDoesNotClaim(): void
    {
        $this->store = new RegistrationStore();
        $manager = new AgentRegistrationManager($this->store->entityManager($this), $this->signer, ['mcp'], 600, 86400, fn (): \DateTimeImmutable => $this->now);
        $body = $manager->register('anonymous', null, null, self::ISSUER, self::CLAIM_URL, self::VERIFY);
        $this->now = $this->now->modify('+300 seconds');
        $attempt = $manager->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $manager->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);
        $this->now = $this->now->modify('+300 seconds');

        self::assertSame(AgentRegistrationManager::RESULT_EXPIRED, $manager->confirm($registration, 7, 'a@b.example', $attempt['user_code']));
    }

    public function testOnlyTheNamedAdministratorCanClaim(): void
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], 'owner@shop.example', self::VERIFY)['claim_attempt'];
        $registration = $this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);

        self::assertSame(AgentRegistrationManager::RESULT_WRONG_ACCOUNT, $this->manager()->confirm($registration, 8, 'other@shop.example', $attempt['user_code']));
        self::assertSame(0, $registration->getFailedCodeAttempts());
        self::assertSame(AgentRegistrationManager::RESULT_CLAIMED, $this->manager()->confirm($registration, 7, 'Owner@Shop.example', $attempt['user_code']));
    }

    public function testFindOpenAttemptIgnoresUnknownEmptyAndRevoked(): void
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $token = $this->attemptToken($attempt['verification_uri']);

        self::assertNull($this->manager()->findOpenAttempt(''));
        self::assertNull($this->manager()->findOpenAttempt('nope'));
        $this->manager()->revoke($body['registration_id']);
        self::assertNull($this->manager()->findOpenAttempt($token));
        self::assertTrue($this->store->rows[0]->isRevoked());
    }

    public function testPollingBeforeTheClaimIsPendingAndRateBound(): void
    {
        $body = $this->anonymous();

        $this->expectOAuthError('authorization_pending', fn () => $this->manager()->redeemClaim($body['claim_token']));
        $this->now = $this->now->modify('+4 seconds');
        $this->expectOAuthError('slow_down', fn () => $this->manager()->redeemClaim($body['claim_token']));
        $this->now = $this->now->modify('+5 seconds');
        $this->expectOAuthError('authorization_pending', fn () => $this->manager()->redeemClaim($body['claim_token']));
        self::assertEquals($this->now, $this->store->rows[0]->getLastPolledAt());
    }

    public function testPollingAfterTheCodeExpiredAsksForANewAttempt(): void
    {
        $body = $this->anonymous();
        $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY);
        $this->now = $this->now->modify('+600 seconds');

        $this->expectOAuthError('expired_token', fn () => $this->manager()->redeemClaim($body['claim_token']));
    }

    public function testPollingAfterTheWindowClosed(): void
    {
        $body = $this->claimed();
        $this->now = $this->now->modify('+3600 seconds');

        $this->expectOAuthError('expired_token', fn () => $this->manager()->redeemClaim($body['claim_token']));
    }

    public function testAClaimIsRedeemedExactlyOnce(): void
    {
        $body = $this->claimed();

        $registration = $this->manager()->redeemClaim($body['claim_token']);

        self::assertSame($body['registration_id'], $registration->getRegistrationId());
        self::assertEquals($this->now, $registration->getClaimRedeemedAt());
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->redeemClaim($body['claim_token']));
    }

    /** Two polls racing: the database decides, the loser gets invalid_grant. */
    public function testALostRaceForTheClaimIsRefused(): void
    {
        $body = $this->claimed();
        $this->store->loseTheRace = true;

        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->redeemClaim($body['claim_token']));
        self::assertNull($this->store->rows[0]->getClaimRedeemedAt());
    }

    public function testRedeemingUnknownOrRevokedClaims(): void
    {
        $body = $this->claimed();

        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->redeemClaim(''));
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->redeemClaim('clm_nope'));
        $this->manager()->revoke($body['registration_id']);
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->redeemClaim($body['claim_token']));
    }

    public function testThePostClaimAssertionExchangesAndSupersedesThePreClaimOne(): void
    {
        $body = $this->claimed();
        $registration = $this->manager()->redeemClaim($body['claim_token']);

        $assertion = $this->manager()->postClaimAssertion($registration, self::ISSUER);

        self::assertSame('2026-11-06T12:00:00.000Z', $assertion['expires']);
        $claims = $this->signer->verify($assertion['assertion']);
        self::assertNotNull($claims);
        self::assertTrue($claims['claimed']);
        self::assertSame($this->now->getTimestamp() + 86400, $claims['exp']);
        self::assertSame($registration, $this->manager()->exchange($assertion['assertion']));
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->exchange($body['identity_assertion']));
    }

    public function testAnAssertionStopsWorkingWhenItExpiresOrTheRegistrationIsRevoked(): void
    {
        $body = $this->claimed();
        $registration = $this->manager()->redeemClaim($body['claim_token']);
        $assertion = $this->manager()->postClaimAssertion($registration, self::ISSUER)['assertion'];

        $this->now = $this->now->modify('+86400 seconds');
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->exchange($assertion));
        $this->now = $this->now->modify('-1 second');
        self::assertSame($registration, $this->manager()->exchange($assertion));

        $this->manager()->revoke($body['registration_id']);
        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->exchange($assertion));
    }

    public function testForgedOrForeignAssertionsAreRefused(): void
    {
        $body = $this->claimed();
        $registration = $this->manager()->redeemClaim($body['claim_token']);
        $assertion = $this->manager()->postClaimAssertion($registration, self::ISSUER)['assertion'];
        $foreign = (new IdentityAssertionSigner('another-secret'))->sign(['sub' => $body['registration_id'], 'exp' => $this->now->getTimestamp() + 60, 'claimed' => true]);
        $unknown = $this->signer->sign(['sub' => 'reg_unknown', 'exp' => $this->now->getTimestamp() + 60, 'claimed' => true]);
        $noExpiry = $this->signer->sign(['sub' => $body['registration_id'], 'claimed' => true]);
        $noSubject = $this->signer->sign(['exp' => $this->now->getTimestamp() + 60, 'claimed' => true]);

        foreach (['', 'a.b.c', $assertion.'x', $foreign, $unknown, $noExpiry, $noSubject] as $candidate) {
            $this->expectOAuthError('invalid_grant', fn () => $this->manager()->exchange($candidate));
        }
    }

    /** A claimed assertion for a registration that somehow is not claimed is refused. */
    public function testAClaimedAssertionNeedsAClaimedRegistration(): void
    {
        $body = $this->anonymous();
        $forged = $this->signer->sign(['sub' => $body['registration_id'], 'exp' => $this->now->getTimestamp() + 60, 'claimed' => true]);

        $this->expectOAuthError('invalid_grant', fn () => $this->manager()->exchange($forged));
    }

    public function testRevokingAnUnknownRegistrationIsANoOp(): void
    {
        $this->anonymous();
        $this->anonymous();
        $flushes = $this->store->flushes;

        $this->manager()->revoke('reg_unknown');
        $this->manager()->revoke($this->store->rows[1]->getRegistrationId());
        $this->manager()->revoke($this->store->rows[1]->getRegistrationId());

        self::assertSame($flushes + 1, $this->store->flushes);
        self::assertFalse($this->store->rows[0]->isRevoked());
        self::assertTrue($this->store->rows[1]->isRevoked());
    }

    public function testThePostClaimScopesAreExposedForTheClaimPage(): void
    {
        self::assertSame(['mcp:read'], $this->manager()->getPostClaimScopes());
    }

    private function manager(): AgentRegistrationManager
    {
        return new AgentRegistrationManager(
            $this->store->entityManager($this),
            $this->signer,
            ['mcp:read'],
            3600,
            86400,
            fn (): \DateTimeImmutable => $this->now,
        );
    }

    /** @return array<string, mixed> */
    private function anonymous(): array
    {
        return $this->manager()->register('anonymous', null, '192.0.2.1', self::ISSUER, self::CLAIM_URL, self::VERIFY);
    }

    /** @return array<string, mixed> */
    private function claimed(): array
    {
        $body = $this->anonymous();
        $attempt = $this->manager()->initiateClaim($body['claim_token'], null, self::VERIFY)['claim_attempt'];
        $registration = $this->manager()->findOpenAttempt($this->attemptToken($attempt['verification_uri']));
        self::assertNotNull($registration);
        self::assertSame(AgentRegistrationManager::RESULT_CLAIMED, $this->manager()->confirm($registration, 7, 'a@b.example', $attempt['user_code']));

        return $body;
    }

    private function attemptToken(string $verificationUri): string
    {
        parse_str((string) parse_url($verificationUri, \PHP_URL_QUERY), $query);

        return (string) $query['claim_attempt_token'];
    }

    private function expectOAuthError(string $error, \Closure $call): void
    {
        try {
            $call();
            self::fail('Expected OAuthException '.$error);
        } catch (OAuthException $e) {
            self::assertSame($error, $e->error);
        }
    }

    private function expectAgentError(string $error, int $status, \Closure $call): void
    {
        try {
            $call();
            self::fail('Expected AgentAuthException '.$error);
        } catch (AgentAuthException $e) {
            self::assertSame($error, $e->error);
            self::assertSame($status, $e->status);
        }
    }
}
