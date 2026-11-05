<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
use Koh\SyliusMcpOAuth\Entity\McpAgentRegistration;
use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthException;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
use Koh\SyliusMcpOAuth\Security\AccountStatusGuard;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * OAuth token endpoint (RFC 6749 §4.1.3, §6). Exchanges an authorization code
 * + PKCE verifier — or a refresh token — for an MCP access token bound to the
 * admin user who consented. Public clients only, so no client authentication:
 * PKCE is the proof for a code, rotation the safeguard for a refresh token.
 *
 * The access token lives `koh_mcp_oauth.access_token_ttl` seconds, and
 * `expires_in` says exactly that: a client caches the token for expires_in, so
 * the two must never disagree. With `refresh_token_ttl` above zero a refresh
 * token comes along; each refresh spends it and hands out a new one
 * ({@see RefreshTokenManager}).
 *
 * The token is bound to the resource of the authorization (RFC 8707). A
 * `resource` parameter here must name the same resource, or the request fails
 * with invalid_target.
 *
 * Before any token is minted — from a code or from a refresh — the
 * administrator the grant belongs to is loaded and checked
 * ({@see AccountStatusGuard}): a disabled or deleted account gets
 * invalid_grant, and a refresh for it also ends the refresh-token family
 * (AUD-011-F01).
 *
 * Two more grants serve the auth.md agent registration
 * ({@see AgentRegistrationManager}): the claim grant, polled by an agent until
 * an administrator has claimed its registration, and the RFC 7523 jwt-bearer
 * grant, which exchanges the post-claim identity assertion for a fresh access
 * token. Both mint tokens for the claiming administrator only; an unclaimed
 * registration never gets one.
 */
final class TokenController extends AbstractController
{
    /** Matches the bundle configuration default. */
    public const DEFAULT_ACCESS_TOKEN_TTL = 3600;

    public const GRANT_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    public const GRANT_AGENT_CLAIM = 'urn:workos:agent-auth:grant-type:claim';

    /** @param ObjectRepository<object>|null $adminUsers the Sylius admin users; null skips the account check (unit tests only) */
    public function __construct(
        private readonly int $accessTokenTtl = self::DEFAULT_ACCESS_TOKEN_TTL,
        private readonly int $refreshTokenTtl = 0,
        private readonly ?RefreshTokenManager $refreshTokens = null,
        private readonly ?ResourceIndicator $resource = null,
        private readonly EndpointRateLimiter $rateLimiter = new EndpointRateLimiter(),
        private readonly CorsPolicy $corsPolicy = new CorsPolicy(),
        private readonly ?ObjectRepository $adminUsers = null,
        private readonly AccountStatusGuard $accountStatus = new AccountStatusGuard(),
        private readonly ?AgentRegistrationManager $agentRegistrations = null,
        private readonly ?AgentContextFactoryInterface $contextFactory = null,
        private readonly bool $agentRegistrationEnabled = true,
    ) {
        if ($accessTokenTtl < 1) {
            throw new \InvalidArgumentException('access_token_ttl must be a positive number of seconds.');
        }
        if ($refreshTokenTtl < 0) {
            throw new \InvalidArgumentException('refresh_token_ttl must be zero (off) or a positive number of seconds.');
        }
    }

    public function __invoke(Request $request, OAuthServer $server, AccessTokenManager $tokens): Response
    {
        $limited = $this->rateLimiter->check('token', $request);
        if (null !== $limited) {
            return $this->corsPolicy->apply($request, $limited);
        }

        $grantType = (string) $request->request->get('grant_type', '');
        $agentRegistration = null;

        try {
            if ($this->agentGrantsEnabled() && \in_array($grantType, [self::GRANT_AGENT_CLAIM, self::GRANT_JWT_BEARER], true)) {
                $agentRegistration = self::GRANT_AGENT_CLAIM === $grantType
                    ? $this->agentRegistrations->redeemClaim((string) $request->request->get('claim_token', ''))
                    : $this->agentRegistrations->exchange((string) $request->request->get('assertion', ''));
                $grant = $this->agentGrant($request, $agentRegistration);
            } else {
                $grant = match ($grantType) {
                    'authorization_code' => $this->authorizationCode($request, $server),
                    'refresh_token' => $this->refresh($request),
                    default => throw new OAuthException('unsupported_grant_type', \sprintf('Supported grant types: %s.', implode(', ', $this->supportedGrantTypes()))),
                };
            }
            $this->assertAccountMayAct($grant);
        } catch (OAuthException $e) {
            return $this->fail($request, $e->error, $e->getMessage());
        }

        $expiresAt = (new \DateTimeImmutable())->modify(\sprintf('+%d seconds', $this->accessTokenTtl));

        $result = $tokens->create(
            adminUserId: $grant['admin_user_id'],
            name: $grant['name'],
            scopes: $grant['scopes'],
            expiresAt: $expiresAt,
            clientId: $grant['client_id'],
            audience: $grant['resource'],
            refreshFamily: $grant['family'],
            ip: $request->getClientIp(),
        );

        $body = [
            'access_token' => $result['token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->accessTokenTtl,
            'scope' => implode(' ', $grant['scopes']),
        ];

        if (null !== $this->refreshTokens && $this->refreshTokenTtl > 0 && null !== $grant['family']) {
            $body['refresh_token'] = $this->refreshTokens->issue(
                $grant['family'],
                $grant['admin_user_id'],
                $grant['client_id'],
                $grant['scopes'],
                $grant['resource'],
                $this->refreshTokenTtl,
            )['token'];
        }

        // AUTH.md Step 4c: the claim grant also returns the post-claim
        // assertion, the agent's way to mint the next access token.
        if (null !== $agentRegistration && self::GRANT_AGENT_CLAIM === $grantType && $this->agentGrantsEnabled()) {
            $assertion = $this->agentRegistrations->postClaimAssertion($agentRegistration, $this->issuer($request));
            $body['identity_assertion'] = $assertion['assertion'];
            $body['assertion_expires'] = $assertion['expires'];
        }

        return $this->cors($request, new JsonResponse($body));
    }

    /** @phpstan-assert-if-true !null $this->agentRegistrations */
    private function agentGrantsEnabled(): bool
    {
        return $this->agentRegistrationEnabled && null !== $this->agentRegistrations;
    }

    /** @return list<string> */
    private function supportedGrantTypes(): array
    {
        $types = ['authorization_code'];
        if (null !== $this->refreshTokens && $this->refreshTokenTtl > 0) {
            $types[] = 'refresh_token';
        }
        if ($this->agentGrantsEnabled()) {
            $types[] = self::GRANT_JWT_BEARER;
            $types[] = self::GRANT_AGENT_CLAIM;
        }

        return $types;
    }

    /**
     * @return array{admin_user_id: int, name: string, scopes: list<string>, client_id: string, resource: string|null, family: string|null}
     */
    private function agentGrant(Request $request, McpAgentRegistration $registration): array
    {
        $adminUserId = $registration->getAdminUserId();
        if (null === $adminUserId) {
            throw new OAuthException('invalid_grant', 'The registration is not claimed.');
        }

        $resource = $this->resource?->canonical($request);
        $this->assertResource($request, $resource);

        return [
            'admin_user_id' => $adminUserId,
            'name' => \sprintf('Agent %s (%s)', $registration->getRegistrationId(), $registration->getType()),
            'scopes' => $registration->getScopes(),
            'client_id' => $registration->getRegistrationId(),
            'resource' => $resource,
            'family' => null,
        ];
    }

    private function issuer(Request $request): string
    {
        if (null !== $this->contextFactory) {
            try {
                return $this->contextFactory->create()->baseUrl;
            } catch (\Throwable) {
                // No channel resolvable: fall back to the request.
            }
        }

        return $request->getSchemeAndHttpHost();
    }

    /**
     * @return array{admin_user_id: int, name: string, scopes: list<string>, client_id: string, resource: string|null, family: string|null}
     */
    private function authorizationCode(Request $request, OAuthServer $server): array
    {
        $payload = $server->consumeCode(
            rawCode: (string) $request->request->get('code', ''),
            clientId: (string) $request->request->get('client_id', ''),
            redirectUri: (string) $request->request->get('redirect_uri', ''),
            codeVerifier: (string) $request->request->get('code_verifier', ''),
        );

        $this->assertResource($request, $payload['resource']);

        return [
            'admin_user_id' => $payload['admin_user_id'],
            'name' => $payload['client']->getClientName(),
            'scopes' => $payload['scopes'],
            'client_id' => $payload['client']->getClientId(),
            'resource' => $payload['resource'],
            'family' => null !== $this->refreshTokens && $this->refreshTokenTtl > 0 ? RefreshTokenManager::newFamily() : null,
        ];
    }

    /**
     * @return array{admin_user_id: int, name: string, scopes: list<string>, client_id: string, resource: string|null, family: string|null}
     */
    private function refresh(Request $request): array
    {
        if (null === $this->refreshTokens || 0 === $this->refreshTokenTtl) {
            throw new OAuthException('unsupported_grant_type', 'Only authorization_code is supported.');
        }

        $clientId = (string) $request->request->get('client_id', '');
        $spent = $this->refreshTokens->rotate((string) $request->request->get('refresh_token', ''), $clientId);
        $this->assertResource($request, $spent->getAudience());

        // RFC 6749 §6: a refresh may narrow the scope, never widen it.
        $scopes = $spent->getScopes();
        $requested = trim((string) $request->request->get('scope', ''));
        if ('' !== $requested) {
            $narrowed = array_values(array_filter(explode(' ', $requested), static fn (string $s): bool => '' !== $s));
            if ([] !== array_diff($narrowed, $scopes)) {
                throw new OAuthException('invalid_scope', 'A refresh cannot add scopes the authorization did not grant.');
            }
            $scopes = $narrowed;
        }

        return [
            'admin_user_id' => $spent->getAdminUserId(),
            'name' => $clientId,
            'scopes' => $scopes,
            'client_id' => $clientId,
            'resource' => $spent->getAudience(),
            'family' => $spent->getFamily(),
        ];
    }

    /**
     * @param array{admin_user_id: int, family: string|null} $grant
     */
    private function assertAccountMayAct(array $grant): void
    {
        if (null === $this->adminUsers) {
            return;
        }

        $user = $this->adminUsers->find($grant['admin_user_id']);
        $refused = !$user instanceof UserInterface;
        if (!$refused) {
            try {
                $this->accountStatus->check($user);
            } catch (AccountStatusException) {
                $refused = true;
            }
        }

        if ($refused) {
            // The rotation already spent the presented refresh token; the
            // rest of the family goes with it, so re-enabling the account
            // does not bring an old agent session back.
            if (null !== $grant['family'] && null !== $this->refreshTokens) {
                $this->refreshTokens->revokeFamily($grant['family']);
            }

            throw new OAuthException('invalid_grant', 'The administrator of this grant may not sign in.');
        }
    }

    private function assertResource(Request $request, ?string $bound): void
    {
        $requested = (string) $request->request->get('resource', '');
        if ('' === $requested) {
            return;
        }

        $matches = null !== $bound
            ? rtrim(strtolower($requested), '/') === rtrim(strtolower($bound), '/')
            : (null === $this->resource || $this->resource->matches($requested, $request));
        if (!$matches) {
            throw new OAuthException('invalid_target', 'The resource does not match the one this grant was issued for.');
        }
    }

    private function fail(Request $request, string $error, string $description): JsonResponse
    {
        return $this->cors($request, new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            Response::HTTP_BAD_REQUEST,
        ));
    }

    private function cors(Request $request, JsonResponse $response): JsonResponse
    {
        $this->corsPolicy->apply($request, $response);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
