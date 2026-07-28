<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Security;

use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Doctrine\Persistence\ObjectRepository;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Authenticates requests to /_mcp by a Bearer MCP access token, resolving it to
 * the owning Sylius admin user. On missing/invalid credentials it returns a 401
 * with a `WWW-Authenticate: Bearer resource_metadata=…` header — the RFC 9728
 * pointer MCP clients follow to discover the OAuth authorization server.
 */
final class McpAccessTokenAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    /** @param ObjectRepository<AdminUserInterface> $adminUsers */
    public function __construct(
        private readonly AccessTokenManager $tokens,
        #[Autowire(service: 'sylius.repository.admin_user')]
        private readonly ObjectRepository $adminUsers,
    ) {
    }

    public function supports(Request $request): bool
    {
        return str_starts_with((string) $request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $raw = trim(substr((string) $request->headers->get('Authorization', ''), 7));

        $token = $this->tokens->findValid($raw);
        if ($token === null) {
            throw new CustomUserMessageAuthenticationException('Invalid or expired MCP access token.');
        }

        $user = $this->adminUsers->find($token->getAdminUserId());
        if (!$user instanceof UserInterface) {
            throw new CustomUserMessageAuthenticationException('The MCP token owner no longer exists.');
        }

        return new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), static fn (): UserInterface => $user));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null; // let the request continue to the MCP controller
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->challenge($request, $exception->getMessageKey());
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return $this->challenge($request, 'Authentication required.');
    }

    private function challenge(Request $request, string $message): Response
    {
        $resourceMetadata = $request->getSchemeAndHttpHost() . '/.well-known/oauth-protected-resource';

        return new JsonResponse(
            ['error' => 'unauthorized', 'error_description' => $message],
            Response::HTTP_UNAUTHORIZED,
            ['WWW-Authenticate' => sprintf('Bearer resource_metadata="%s"', $resourceMetadata)],
        );
    }
}
