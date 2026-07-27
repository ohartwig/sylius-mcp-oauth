<?php

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Controller;

use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
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
    public function __invoke(Request $request, AccessTokenManager $tokens): JsonResponse
    {
        $tokens->revokeRaw((string) $request->request->get('token', ''));

        $response = new JsonResponse(null, Response::HTTP_OK);
        $response->headers->set('Access-Control-Allow-Origin', '*');

        return $response;
    }
}
