<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
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
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * OAuth authorization endpoint. Lives under the admin firewall, so an
 * unauthenticated request is redirected to the Sylius admin login and returns
 * here afterwards. GET shows a consent screen; POST (with CSRF) issues a
 * single-use authorization code bound to the logged-in admin user and redirects
 * back to the client with `?code=…&state=…`. PKCE S256 is mandatory.
 *
 * The consent screen is the bundle's `@KohSyliusMcpOAuth/oauth/authorize.html.twig`;
 * a host overrides it the Symfony way, at
 * `templates/bundles/KohSyliusMcpOAuthBundle/oauth/authorize.html.twig`.
 * User-facing text lives in the `koh_mcp_oauth` translation domain.
 */
final class AuthorizeController extends AbstractController
{
    private const CSRF_ID = 'mcp_oauth_authorize';

    public const TEMPLATE = '@KohSyliusMcpOAuth/oauth/authorize.html.twig';

    public const TRANSLATION_DOMAIN = 'koh_mcp_oauth';

    /**
     * English fallbacks, used when no translator is available or the catalogue
     * lacks a key — an error page must never show a bare translation key.
     */
    private const FALLBACK_MESSAGES = [
        'error.title' => 'MCP authorisation failed',
        'error.invalid_client' => 'Unknown client_id, or a redirect_uri this client has not registered.',
        'error.redirect_uri_not_allowed' => 'This redirect_uri is not on the allow-list of this server. Ask the operator to add it to koh_mcp_oauth.allowed_redirect_uris.',
        'error.not_signed_in' => 'No administrator is signed in.',
        'error.invalid_csrf' => 'The consent form has expired or is invalid. Please start again from your MCP client.',
        'error.code' => 'Error code',
    ];

    /**
     * RFC 7636 §4.2: base64url(SHA-256) is 43 characters; the unreserved
     * alphabet and 43–128 length bound what any conforming client can send.
     */
    private const CODE_CHALLENGE_PATTERN = '/^[A-Za-z0-9\-._~]{43,128}$/';

    public function __construct(
        private readonly ?TranslatorInterface $translator = null,
    ) {
    }

    public function __invoke(Request $request, OAuthServer $server): Response
    {
        $params = $request->isMethod('POST') ? $request->request : $request->query;

        $clientId = (string) $params->get('client_id', '');
        $redirectUri = (string) $params->get('redirect_uri', '');
        $client = $server->findClient($clientId);

        // A bad client_id/redirect_uri must NOT be echoed back via redirect
        // (open-redirect / token-leak guard) — render an on-site error instead.
        if (!$client instanceof McpOAuthClient || !$client->hasRedirectUri($redirectUri)) {
            return $this->error('error.invalid_client', 'invalid_request');
        }

        // Registered is not enough: the operator's allow-list decides, and it
        // may have been introduced or narrowed after this client registered.
        if (!$server->isRedirectUriAllowed($redirectUri)) {
            return $this->error('error.redirect_uri_not_allowed', 'invalid_request');
        }

        $state = (string) $params->get('state', '');
        $codeChallenge = (string) $params->get('code_challenge', '');
        $challengeMethod = (string) $params->get('code_challenge_method', 'S256');
        $scopes = $this->resolveScopes((string) $params->get('scope', 'mcp'));

        // From here on, protocol errors are reported to the (validated) client.
        if ((string) $params->get('response_type', 'code') !== 'code') {
            return $this->deny($redirectUri, 'unsupported_response_type', $state);
        }
        if ($challengeMethod !== 'S256' || 1 !== preg_match(self::CODE_CHALLENGE_PATTERN, $codeChallenge)) {
            return $this->deny($redirectUri, 'invalid_request', $state);
        }
        if ($scopes === null) {
            return $this->deny($redirectUri, 'invalid_scope', $state);
        }

        $admin = $this->getUser();
        if (!$admin instanceof UserInterface || !method_exists($admin, 'getId')) {
            return $this->error('error.not_signed_in', 'access_denied');
        }

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid(self::CSRF_ID, (string) $request->request->get('_csrf_token'))) {
                return $this->error('error.invalid_csrf', 'invalid_request');
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

        $response = $this->render(self::TEMPLATE, [
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
            'redirect_uri' => $redirectUri,
            'translation_domain' => self::TRANSLATION_DOMAIN,
        ]);

        return $this->hardenConsentResponse($response);
    }

    /** @return list<string>|null null = an unsupported scope was requested */
    private function resolveScopes(string $scope): ?array
    {
        // Two things are dropped here, and only one of them is uncontroversial:
        // the empty string, which is what repeated spaces between scopes leave
        // behind, and the literal "0", which the callback-less array_filter()
        // discarded just as silently. The condition is spelled out so the second
        // one stops being invisible; it does not change what happens.
        //
        // What happens is the part that wants a decision. A dropped scope is not
        // a refused scope: "mcp 0" is authorised today as if only "mcp" had been
        // asked for, and "0" alone falls through to the default below. An
        // unsupported scope anywhere else in this method ends the request with
        // invalid_scope, and for an authorization endpoint that is very probably
        // the right answer for "0" as well — issuing a token for less than was
        // requested, without saying so, is the failure mode OAuth's error
        // responses exist to prevent. Making it so is a deliberate change to the
        // auth path, not a by-product of satisfying a static analyser, so it is
        // left as it is until it is decided. The change, when it comes, is to
        // remove the '0' !== $s half and let the supported-scope loop reject it.
        $requested = array_values(array_filter(
            explode(' ', trim($scope)),
            static fn (string $s): bool => '' !== $s && '0' !== $s,
        ));
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

    private function error(string $key, string $oauthError): Response
    {
        $title = htmlspecialchars($this->trans('error.title'), \ENT_QUOTES);
        $lang = htmlspecialchars(str_replace('_', '-', $this->translator?->getLocale() ?? 'en'), \ENT_QUOTES);

        return $this->hardenConsentResponse(new Response(
            '<!doctype html><html lang="' . $lang . '"><meta charset="utf-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
            . '<title>' . $title . '</title>'
            . '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5">'
            . '<main><h1>' . $title . '</h1><p role="alert">' . htmlspecialchars($this->trans($key), \ENT_QUOTES) . '</p>'
            . '<p>' . htmlspecialchars($this->trans('error.code'), \ENT_QUOTES) . ': <code>' . htmlspecialchars($oauthError, \ENT_QUOTES) . '</code></p>'
            . '</main></body></html>',
            Response::HTTP_BAD_REQUEST,
            ['Content-Type' => 'text/html; charset=utf-8'],
        ));
    }

    private function trans(string $key): string
    {
        $fallback = self::FALLBACK_MESSAGES[$key] ?? $key;
        if (null === $this->translator) {
            return $fallback;
        }

        $translated = $this->translator->trans($key, [], self::TRANSLATION_DOMAIN);

        return $translated === $key ? $fallback : $translated;
    }

    /**
     * The consent screen must not be framed (clickjacking an admin into
     * approving, RFC 6819 §4.4.1.9) and must not be cached.
     */
    private function hardenConsentResponse(Response $response): Response
    {
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Referrer-Policy', 'no-referrer');

        return $response;
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
