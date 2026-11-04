<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Security;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\DependencyInjection\McpUserCheckerPass;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Koh\SyliusMcpOAuth\Security\AccountStatusGuard;
use Koh\SyliusMcpOAuth\Security\McpAccessTokenAuthenticator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\AdminUser;
use Sylius\Component\User\Security\Checker\EnabledUserChecker;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\User\ChainUserChecker;
use Symfony\Component\Security\Core\User\InMemoryUserChecker;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticatorManager;

/**
 * AUD-011-F01: disabling a Sylius administrator must disable their agent.
 *
 * Before the fix the bearer authenticator accepted any user object the admin
 * repository returned, the `mcp` firewall ran Symfony's default checker
 * (InMemoryUserChecker, which ignores Sylius users), and nothing put Sylius's
 * EnabledUserChecker into the `mcp` chain. The refresh half of the finding is
 * covered in {@see \Koh\SyliusMcpOAuth\Tests\Controller\TokenRefreshTest}.
 */
#[CoversClass(McpAccessTokenAuthenticator::class)]
#[CoversClass(AccountStatusGuard::class)]
#[CoversClass(McpUserCheckerPass::class)]
final class DisabledAdministratorTest extends TestCase
{
    private const RAW = 'tbmcp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

    /** The finding's reproduction: this returned a Passport before the fix. */
    public function testF01DisabledAdminStillAuthenticates(): void
    {
        $authenticator = $this->authenticator($this->administrator(enabled: false));

        $this->expectException(CustomUserMessageAuthenticationException::class);
        $this->expectExceptionMessage('The MCP token owner may not sign in.');

        $authenticator->authenticate($this->bearerRequest());
    }

    public function testADisabledAdministratorsBearerAnswers401AtTheFirewall(): void
    {
        $manager = new AuthenticatorManager([$this->authenticator($this->administrator(enabled: false))], new TokenStorage(), new EventDispatcher(), 'mcp');

        $request = $this->bearerRequest();
        self::assertNotFalse($manager->supports($request));
        $response = $manager->authenticateRequest($request);

        self::assertNotNull($response);
        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertStringContainsString('resource_metadata=', (string) $response->headers->get('WWW-Authenticate'));
    }

    public function testAnEnabledAdministratorStillAuthenticates(): void
    {
        $admin = $this->administrator(enabled: true);

        $passport = $this->authenticator($admin)->authenticate($this->bearerRequest());

        self::assertSame($admin, $passport->getUser());
    }

    public function testTheApplicationsUserCheckerDecides(): void
    {
        // A locked account (or anything else the application refuses) is
        // refused as well: the guard runs the application's checker, it does
        // not re-implement it.
        $checker = $this->createStub(UserCheckerInterface::class);
        $checker->method('checkPreAuth')->willThrowException(new LockedException());

        $this->expectException(CustomUserMessageAuthenticationException::class);

        $this->authenticator($this->administrator(enabled: true), new AccountStatusGuard($checker))
            ->authenticate($this->bearerRequest());
    }

    public function testTheDefaultFirewallCheckerIgnoresSyliusUsers(): void
    {
        // Why the firewall line alone was not enough before: Symfony's default
        // checker returns silently for a disabled Sylius administrator.
        (new InMemoryUserChecker())->checkPreAuth($this->administrator(enabled: false));

        $this->addToAssertionCount(1);
    }

    public function testTheMcpCheckerChainContainsSyliusEnabledUserChecker(): void
    {
        $container = new ContainerBuilder();
        $container->register(McpUserCheckerPass::SYLIUS_ENABLED_CHECKER, EnabledUserChecker::class)
            ->setArguments([null])
            ->addTag('security.user_checker.admin', ['priority' => 100]);
        // What SecurityBundle registers for a firewall named "mcp".
        $container->register('security.user_checker.chain.mcp', ChainUserChecker::class)
            ->addArgument(new TaggedIteratorArgument(McpUserCheckerPass::FIREWALL_TAG))
            ->setPublic(true);
        $container->addCompilerPass(new McpUserCheckerPass());
        $container->compile();

        $chain = $container->get('security.user_checker.chain.mcp');
        self::assertInstanceOf(ChainUserChecker::class, $chain);

        $this->expectException(DisabledException::class);
        @$chain->checkPreAuth($this->administrator(enabled: false));
    }

    public function testThePassLeavesAContainerWithoutSyliusAlone(): void
    {
        $container = new ContainerBuilder();
        (new McpUserCheckerPass())->process($container);

        self::assertFalse($container->hasDefinition(McpUserCheckerPass::SYLIUS_ENABLED_CHECKER));
    }

    private function administrator(bool $enabled): AdminUser
    {
        $admin = new AdminUser();
        $admin->setUsername('former-colleague');
        $admin->setEnabled($enabled);

        return $admin;
    }

    private function bearerRequest(): Request
    {
        $request = new Request();
        $request->headers->set('Authorization', 'Bearer '.self::RAW);

        return $request;
    }

    private function authenticator(UserInterface $admin, ?AccountStatusGuard $guard = null): McpAccessTokenAuthenticator
    {
        $token = new McpAccessToken(tokenHash: hash('sha256', self::RAW), adminUserId: 7, name: 'agent');

        $tokens = $this->createStub(EntityRepository::class);
        $tokens->method('findOneBy')->willReturnCallback(
            static fn (array $criteria): ?McpAccessToken => $criteria['tokenHash'] === hash('sha256', self::RAW) ? $token : null,
        );
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($tokens);

        $admins = $this->createStub(ObjectRepository::class);
        $admins->method('find')->willReturn($admin);

        return null === $guard
            ? new McpAccessTokenAuthenticator(new AccessTokenManager($entityManager), $admins)
            : new McpAccessTokenAuthenticator(new AccessTokenManager($entityManager), $admins, accountStatus: $guard);
    }
}
