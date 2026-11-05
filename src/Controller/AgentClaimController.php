<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\Agent\AgentRegistrationManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * The `verification_uri` of the auth.md claim ceremony (AUTH.md Step 4b).
 *
 * Under /admin, so the admin firewall sends an unauthenticated visitor to the
 * Sylius admin login and back. The signed-in administrator sees which agent
 * registration is asking, which access claiming grants, and types the user
 * code the agent showed them. That — and nothing else — turns an agent
 * registration into one that can obtain an MCP token, acting as this
 * administrator.
 *
 * The page is `@KohSyliusMcpOAuth/agent/claim.html.twig`; override it at
 * `templates/bundles/KohSyliusMcpOAuthBundle/agent/claim.html.twig`.
 */
final class AgentClaimController extends AbstractController
{
    public const TEMPLATE = '@KohSyliusMcpOAuth/agent/claim.html.twig';

    private const CSRF_ID = 'mcp_agent_claim';

    public function __construct(
        private readonly AgentRegistrationManager $registrations,
        private readonly bool $enabled = true,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if (!$this->enabled) {
            throw $this->createNotFoundException();
        }

        $params = $request->isMethod('POST') ? $request->request : $request->query;
        $attemptToken = (string) $params->get('claim_attempt_token', '');
        $registration = $this->registrations->findOpenAttempt($attemptToken);

        $admin = $this->getUser();
        if (!$admin instanceof UserInterface || !method_exists($admin, 'getId')) {
            throw $this->createAccessDeniedException();
        }
        $adminEmail = method_exists($admin, 'getEmail') ? (string) $admin->getEmail() : $admin->getUserIdentifier();

        if (null === $registration) {
            return $this->page('invalid', Response::HTTP_NOT_FOUND);
        }

        $state = 'form';
        $status = Response::HTTP_OK;
        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid(self::CSRF_ID, (string) $request->request->get('_csrf_token'))) {
                return $this->page('invalid_csrf', Response::HTTP_BAD_REQUEST);
            }

            $result = $this->registrations->confirm(
                $registration,
                (int) $admin->getId(),
                $adminEmail,
                (string) $request->request->get('user_code', ''),
            );
            if (AgentRegistrationManager::RESULT_WRONG_CODE !== $result) {
                return $this->page($result, AgentRegistrationManager::RESULT_CLAIMED === $result ? Response::HTTP_OK : Response::HTTP_BAD_REQUEST);
            }
            $state = 'wrong_code';
            $status = Response::HTTP_BAD_REQUEST;
        }

        return $this->page($state, $status, [
            'registration' => $registration,
            'admin_label' => $adminEmail,
            'claim_attempt_token' => $attemptToken,
            'attempts_left' => AgentRegistrationManager::MAX_CODE_ATTEMPTS - $registration->getFailedCodeAttempts(),
            'csrf_id' => self::CSRF_ID,
        ]);
    }

    /** @param array<string, mixed> $parameters */
    private function page(string $state, int $status, array $parameters = []): Response
    {
        $response = $this->render(self::TEMPLATE, $parameters + [
            'state' => $state,
            'scopes' => $this->registrations->getPostClaimScopes(),
            'translation_domain' => AuthorizeController::TRANSLATION_DOMAIN,
        ]);
        $response->setStatusCode($status);
        // Same hardening as the OAuth consent screen: no framing, no caching,
        // and the attempt token in the URL never leaves as a Referer.
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Referrer-Policy', 'no-referrer');

        return $response;
    }
}
