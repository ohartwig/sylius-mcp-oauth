<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Admin;

use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\OAuthServer;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * MCP tokens in the Sylius admin: who holds which token, through which
 * client, with which scopes, used when and from where — and a button to end
 * it.
 *
 * Until now a token could be revoked by the client that held it
 * (/mcp/oauth/revoke) or by someone with a database shell. The administrator
 * whose identity a token carries could do neither from the admin.
 *
 * Every administrator sees and revokes their own tokens. Holders of
 * `koh_mcp_oauth.admin.overview_role` see and revoke everyone's.
 *
 * Revoking a token that came from a refresh-token family revokes the family:
 * otherwise the client would simply refresh it back.
 *
 * Under /admin, so the admin firewall covers it.
 */
final class TokenAdminController extends AbstractController
{
    public const TEMPLATE = '@KohSyliusMcpOAuth/admin/tokens.html.twig';

    /**
     * @param ObjectRepository<AdminUserInterface> $adminUsers
     * @param string|null                          $overviewRole role that sees and revokes every administrator's tokens; null: everyone sees only their own
     */
    public function __construct(
        private readonly AccessTokenManager $tokens,
        private readonly OAuthServer $server,
        private readonly ObjectRepository $adminUsers,
        private readonly ?RefreshTokenManager $refreshTokens = null,
        private readonly ?string $overviewRole = null,
    ) {
    }

    public function index(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMINISTRATION_ACCESS');

        $tokens = $this->seesAll()
            ? $this->tokens->findRecent()
            : $this->tokens->findForAdminUser($this->currentAdminId());

        $owners = [];
        $clients = [];
        foreach ($tokens as $token) {
            $owners[$token->getAdminUserId()] ??= $this->ownerLabel($token->getAdminUserId());
            $clientId = $token->getClientId();
            if (null !== $clientId) {
                $clients[$clientId] ??= $this->server->findClient($clientId)?->getClientName() ?? $clientId;
            }
        }

        $response = $this->render(self::TEMPLATE, [
            'tokens' => array_map(fn (McpAccessToken $token): array => [
                'token' => $token,
                'owner' => $owners[$token->getAdminUserId()],
                'client' => null !== $token->getClientId() ? $clients[$token->getClientId()] : null,
                'status' => $this->status($token),
            ], $tokens),
            'translation_domain' => 'koh_mcp_oauth',
        ]);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    public function revoke(int $id, Request $request): Response
    {
        $this->denyAccessUnlessGranted('ROLE_ADMINISTRATION_ACCESS');

        if (!$this->isCsrfTokenValid('mcp_token_revoke_'.$id, (string) $request->request->get('_token'))) {
            throw $this->createAccessDeniedException('Invalid CSRF token.');
        }

        $token = $this->tokens->find($id);
        // Someone else's token reads like no token, unless the overview role
        // allows managing all of them.
        if (!$token instanceof McpAccessToken || (!$this->seesAll() && $token->getAdminUserId() !== $this->currentAdminId())) {
            throw $this->createNotFoundException();
        }

        $this->tokens->revoke($token);
        if (null !== $token->getRefreshFamily()) {
            $this->refreshTokens?->revokeFamily($token->getRefreshFamily());
        }

        $this->addFlash('success', 'admin.tokens.revoked');

        return $this->redirectToRoute('mcp_oauth_admin_tokens');
    }

    private function seesAll(): bool
    {
        return null !== $this->overviewRole && '' !== $this->overviewRole && $this->isGranted($this->overviewRole);
    }

    private function currentAdminId(): int
    {
        $user = $this->getUser();
        if (!\is_object($user) || !method_exists($user, 'getId')) {
            throw $this->createAccessDeniedException();
        }

        return (int) $user->getId();
    }

    private function ownerLabel(int $adminUserId): string
    {
        $admin = $this->adminUsers->find($adminUserId);

        return $admin instanceof AdminUserInterface ? ($admin->getEmail() ?? $admin->getUserIdentifier()) : '#'.$adminUserId;
    }

    private function status(McpAccessToken $token): string
    {
        if ($token->isRevoked()) {
            return 'revoked';
        }

        return $token->isValid() ? 'active' : 'expired';
    }
}
