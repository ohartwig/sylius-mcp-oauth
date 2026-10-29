<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Security;

use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\Http\EndpointRateLimiter;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\OAuth\ResourceIndicator;
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
 *
 * A token bound to a resource (RFC 8707) is accepted only at that resource.
 * The facts about the token — id, client, scopes, audience — go onto the
 * security token as attributes, under the names koh/sylius-mcp reads
 * ({@see self::ATTRIBUTE_SCOPES} and siblings): that is how the MCP server
 * learns what the token may do without depending on this package.
 *
 * Every authenticated request then spends one unit of the credential's rate
 * limit (`rate_limits.mcp`). Over the limit the request ends here with a 429
 * and `Retry-After`, before any tool runs. The check sits after
 * authentication on purpose: only then is the credential known, and an
 * unauthenticated request is already answered with a 401.
 */
final class McpAccessTokenAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public const ATTRIBUTE_TOKEN_ID = 'koh_mcp.token_id';

    public const ATTRIBUTE_CLIENT_ID = 'koh_mcp.client_id';

    public const ATTRIBUTE_SCOPES = 'koh_mcp.scopes';

    public const ATTRIBUTE_AUDIENCE = 'koh_mcp.audience';

    /** The limiter key of {@see EndpointRateLimiter::credentialKey()}; never the bearer value. */
    public const ATTRIBUTE_RATE_LIMIT_KEY = 'koh_mcp.rate_limit_key';

    private const PASSPORT_TOKEN = 'koh_mcp.access_token';

    /** @param ObjectRepository<AdminUserInterface> $adminUsers */
    public function __construct(
        private readonly AccessTokenManager $tokens,
        #[Autowire(service: 'sylius.repository.admin_user')]
        private readonly ObjectRepository $adminUsers,
        private readonly ?ResourceIndicator $resource = null,
        private readonly ?EndpointRateLimiter $rateLimiter = null,
    ) {
    }

    public function supports(Request $request): bool
    {
        return str_starts_with($request->headers->get('Authorization', ''), 'Bearer ');
    }

    public function authenticate(Request $request): Passport
    {
        $raw = trim(substr($request->headers->get('Authorization', ''), 7));

        $token = $this->tokens->findValid($raw, $request->getClientIp());
        if ($token === null) {
            throw new CustomUserMessageAuthenticationException('Invalid or expired MCP access token.');
        }

        // Audience binding: a token issued for another resource is refused
        // here, however valid it is otherwise. Tokens without an audience
        // (issued before 3.0, or on the CLI) are accepted as before.
        $audience = $token->getAudience();
        if (null !== $audience && null !== $this->resource && !$this->resource->matches($audience, $request)) {
            throw new CustomUserMessageAuthenticationException('This MCP access token was issued for a different resource.');
        }

        $user = $this->adminUsers->find($token->getAdminUserId());
        if (!$user instanceof UserInterface) {
            throw new CustomUserMessageAuthenticationException('The MCP token owner no longer exists.');
        }

        $passport = new SelfValidatingPassport(new UserBadge($user->getUserIdentifier(), static fn (): UserInterface => $user));
        $passport->setAttribute(self::PASSPORT_TOKEN, $token);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $securityToken = parent::createToken($passport, $firewallName);

        $token = $passport->getAttribute(self::PASSPORT_TOKEN);
        if ($token instanceof McpAccessToken) {
            $securityToken->setAttribute(self::ATTRIBUTE_TOKEN_ID, $token->getId());
            $securityToken->setAttribute(self::ATTRIBUTE_CLIENT_ID, $token->getClientId());
            $securityToken->setAttribute(self::ATTRIBUTE_SCOPES, $token->getScopes());
            $securityToken->setAttribute(self::ATTRIBUTE_AUDIENCE, $token->getAudience());
            $securityToken->setAttribute(self::ATTRIBUTE_RATE_LIMIT_KEY, EndpointRateLimiter::credentialKey($token));
        }

        return $securityToken;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        // A response here answers the caller instead of running the MCP
        // controller; that is exactly what an exhausted limit should do.
        if (null !== $this->rateLimiter && $token->hasAttribute(self::ATTRIBUTE_RATE_LIMIT_KEY)) {
            $key = $token->getAttribute(self::ATTRIBUTE_RATE_LIMIT_KEY);
            if (\is_string($key) && '' !== $key) {
                return $this->rateLimiter->checkCredential($key);
            }
        }

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
