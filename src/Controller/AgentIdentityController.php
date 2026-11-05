<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusMcpOAuth\Agent\AgentAuthException;
use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * The auth.md v0.6.0 registration endpoints: `identity_endpoint`
 * (POST {"type": "anonymous"} or {"type": "service_auth", "login_hint": …})
 * and `claim_endpoint` (POST {"claim_token": …, "email": …}).
 *
 * Both are open — an agent has nothing to authenticate with yet — and
 * rate-limited per client address (`koh_mcp_oauth.rate_limits.identity`).
 * Neither grants access: see {@see AgentRegistrationManager}.
 */
final class AgentIdentityController
{
    public const IDENTITY_PATH = '/mcp/oauth/agent/identity';
    public const CLAIM_PATH = '/mcp/oauth/agent/identity/claim';
    public const VERIFICATION_PATH = '/admin/mcp/claim';

    public function __construct(
        private readonly AgentRegistrationManager $registrations,
        private readonly AgentContextFactoryInterface $contextFactory,
        private readonly EndpointRateLimiter $rateLimiter = new EndpointRateLimiter(),
        private readonly CorsPolicy $corsPolicy = new CorsPolicy(),
        private readonly bool $enabled = true,
    ) {
    }

    public function identity(Request $request): Response
    {
        return $this->handle($request, function (array $body) use ($request): JsonResponse {
            $context = $this->contextFactory->create();
            $type = $body['type'] ?? null;
            $loginHint = $body['login_hint'] ?? null;

            return new JsonResponse($this->registrations->register(
                type: \is_string($type) ? $type : '',
                loginHint: \is_string($loginHint) ? $loginHint : null,
                ip: $request->getClientIp(),
                issuer: $context->baseUrl,
                claimUrl: $context->url(self::CLAIM_PATH),
                verificationBase: $context->url(self::VERIFICATION_PATH),
            ));
        });
    }

    public function claim(Request $request): Response
    {
        return $this->handle($request, function (array $body): JsonResponse {
            $claimToken = $body['claim_token'] ?? null;
            $email = $body['email'] ?? null;

            return new JsonResponse($this->registrations->initiateClaim(
                \is_string($claimToken) ? $claimToken : '',
                \is_string($email) ? $email : null,
                $this->contextFactory->create()->url(self::VERIFICATION_PATH),
            ));
        });
    }

    /** @param \Closure(array<string, mixed>): JsonResponse $action */
    private function handle(Request $request, \Closure $action): Response
    {
        if (!$this->enabled) {
            throw new NotFoundHttpException('Agent registration is not enabled.');
        }

        $limited = $this->rateLimiter->check('identity', $request, 'rate_limited');
        if (null !== $limited) {
            return $this->corsPolicy->apply($request, $limited);
        }

        try {
            $decoded = json_decode($request->getContent(), true, 8, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $decoded = null;
        }

        try {
            if (!\is_array($decoded) || array_is_list($decoded)) {
                throw new AgentAuthException('invalid_request', 'The body must be a JSON object.');
            }
            /** @var array<string, mixed> $decoded */
            $response = $action($decoded);
        } catch (AgentAuthException $e) {
            $response = new JsonResponse(['error' => $e->error, 'error_description' => $e->getMessage()], $e->status);
        }

        $response->headers->set('Cache-Control', 'no-store');

        return $this->corsPolicy->apply($request, $response);
    }
}
