<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\Entity\McpOAuthClient;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * OAuth authorization endpoint. Lives under the admin firewall, so an
 * unauthenticated request is redirected to the Sylius admin login and returns
 * here afterwards. GET shows a consent screen; POST (with CSRF) issues a
 * single-use authorization code bound to the logged-in admin user and redirects
 * back to the client with `?code=…&state=…`. PKCE S256 is mandatory.
 */
final class AuthorizeController extends AbstractController
{
    private const CSRF_ID = 'mcp_oauth_authorize';

    public function __invoke(Request $request, OAuthServer $server): Response
    {
        $params = $request->isMethod('POST') ? $request->request : $request->query;

        $clientId = (string) $params->get('client_id', '');
        $redirectUri = (string) $params->get('redirect_uri', '');
        $client = $server->findClient($clientId);

        // A bad client_id/redirect_uri must NOT be echoed back via redirect
        // (open-redirect / token-leak guard) — render an on-site error instead.
        if (!$client instanceof McpOAuthClient || !$client->hasRedirectUri($redirectUri)) {
            return $this->error('Ungültiger client_id oder redirect_uri.');
        }

        $state = (string) $params->get('state', '');
        $codeChallenge = (string) $params->get('code_challenge', '');
        $challengeMethod = (string) $params->get('code_challenge_method', 'S256');
        $scopes = $this->resolveScopes((string) $params->get('scope', 'mcp'));

        // From here on, protocol errors are reported to the (validated) client.
        if ((string) $params->get('response_type', 'code') !== 'code') {
            return $this->deny($redirectUri, 'unsupported_response_type', $state);
        }
        if ($codeChallenge === '' || $challengeMethod !== 'S256') {
            return $this->deny($redirectUri, 'invalid_request', $state);
        }
        if ($scopes === null) {
            return $this->deny($redirectUri, 'invalid_scope', $state);
        }

        $admin = $this->getUser();
        if (!$admin instanceof UserInterface || !method_exists($admin, 'getId')) {
            return $this->error('Kein angemeldeter Admin-Benutzer.');
        }

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid(self::CSRF_ID, (string) $request->request->get('_csrf_token'))) {
                return $this->error('Ungültiges CSRF-Token. Bitte erneut versuchen.');
            }

            if ($request->request->get('decision') !== 'approve') {
                return $this->deny($redirectUri, 'access_denied', $state);
            }

            $code = $server->issueCode(
                client: $client,
                adminUserId: (int) $admin->getId(),
                redirectUri: $redirectUri,
                scopes: $scopes,
                codeChallenge: $codeChallenge,
                codeChallengeMethod: $challengeMethod,
            );

            return new RedirectResponse($this->appendQuery($redirectUri, ['code' => $code, 'state' => $state]));
        }

        return $this->render('mcp/oauth/authorize.html.twig', [
            'client' => $client,
            'admin_label' => method_exists($admin, 'getEmail') ? (string) $admin->getEmail() : $admin->getUserIdentifier(),
            'scopes' => $scopes,
            'csrf_id' => self::CSRF_ID,
            'query' => [
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
                'state' => $state,
                'scope' => implode(' ', $scopes),
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => $challengeMethod,
                'response_type' => 'code',
            ],
        ]);
    }

    /** @return list<string>|null null = an unsupported scope was requested */
    private function resolveScopes(string $scope): ?array
    {
        $requested = array_values(array_filter(explode(' ', trim($scope))));
        if ($requested === []) {
            return ['mcp'];
        }
        foreach ($requested as $s) {
            if (!\in_array($s, OAuthServer::SUPPORTED_SCOPES, true)) {
                return null;
            }
        }

        return $requested;
    }

    private function deny(string $redirectUri, string $error, string $state): RedirectResponse
    {
        return new RedirectResponse($this->appendQuery($redirectUri, ['error' => $error, 'state' => $state]));
    }

    private function error(string $message): Response
    {
        return new Response(
            '<!doctype html><meta charset="utf-8"><title>MCP-Autorisierung</title>'
            . '<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">'
            . '<h1>MCP-Autorisierung fehlgeschlagen</h1><p>' . htmlspecialchars($message, \ENT_QUOTES) . '</p></body>',
            Response::HTTP_BAD_REQUEST,
            ['Content-Type' => 'text/html; charset=utf-8'],
        );
    }

    /** @param array<string, string> $extra */
    private function appendQuery(string $url, array $extra): string
    {
        $extra = array_filter($extra, static fn (string $v): bool => $v !== '');
        if ($extra === []) {
            return $url;
        }
        $separator = str_contains($url, '?') ? '&' : '?';

        return $url . $separator . http_build_query($extra);
    }
}
