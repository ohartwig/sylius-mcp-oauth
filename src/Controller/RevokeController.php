<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\Http\CorsPolicy;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\RefreshTokenManager;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * OAuth token revocation (RFC 7009). Always responds 200, whether or not the
 * token existed, so it does not leak token validity.
 */
final class RevokeController extends AbstractController
{
    public function __construct(
        private readonly ?RefreshTokenManager $refreshTokens = null,
        private readonly CorsPolicy $corsPolicy = new CorsPolicy(),
    ) {
    }

    public function __invoke(Request $request, AccessTokenManager $tokens): JsonResponse
    {
        $raw = (string) $request->request->get('token', '');

        // Either kind of token; the prefix says which. A refresh token takes
        // its whole family along (RFC 7009 §2.1 allows it, and a client that
        // revokes its refresh token means to end the authorization).
        if (str_starts_with($raw, RefreshTokenManager::PREFIX)) {
            $this->refreshTokens?->revokeRaw($raw);
        } else {
            $tokens->revokeRaw($raw);
        }

        $response = new JsonResponse(null, Response::HTTP_OK);
        $this->corsPolicy->apply($request, $response);

        return $response;
    }
}
