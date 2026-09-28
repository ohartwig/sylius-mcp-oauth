<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Command;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\Persistence\ObjectRepository;
use Koh\SyliusMcpOAuth\Command\CreateMcpTokenCommand;
use Koh\SyliusMcpOAuth\Entity\McpAccessToken;
use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * THR-AGENT-020: a CLI token used to live forever unless the operator
 * remembered --ttl-days. It now expires after a finite default, and a token
 * that never expires has to be asked for by name.
 */
#[CoversClass(CreateMcpTokenCommand::class)]
final class CreateMcpTokenCommandTest extends TestCase
{
    /** @var list<McpAccessToken> */
    private array $persisted = [];

    public function testATokenWithoutOptionsExpiresAfterTheDefault(): void
    {
        $before = new \DateTimeImmutable();
        $tester = $this->runCommand(['user' => 'admin@example.test']);
        $after = new \DateTimeImmutable();

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $expiresAt = $this->onlyToken()->getExpiresAt();
        self::assertNotNull($expiresAt, 'a CLI token must not be unlimited by default');
        self::assertGreaterThanOrEqual($before->modify('+90 days')->getTimestamp(), $expiresAt->getTimestamp());
        self::assertLessThanOrEqual($after->modify('+90 days')->getTimestamp(), $expiresAt->getTimestamp());
        self::assertStringNotContainsString('Expires: never', $tester->getDisplay());
    }

    public function testTtlDaysSetsTheLifetime(): void
    {
        $before = new \DateTimeImmutable();
        $tester = $this->runCommand(['user' => 'admin@example.test', '--ttl-days' => '365']);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        $expiresAt = $this->onlyToken()->getExpiresAt();
        self::assertNotNull($expiresAt);
        self::assertGreaterThanOrEqual($before->modify('+365 days')->getTimestamp(), $expiresAt->getTimestamp());
        self::assertLessThan($before->modify('+366 days')->getTimestamp(), $expiresAt->getTimestamp());
    }

    public function testANonExpiringTokenNeedsTheExplicitOptIn(): void
    {
        $tester = $this->runCommand(['user' => 'admin@example.test', '--no-expiry' => true]);

        self::assertSame(Command::SUCCESS, $tester->getStatusCode());
        self::assertNull($this->onlyToken()->getExpiresAt());
        self::assertStringContainsString('Expires: never', $tester->getDisplay());
    }

    public function testTtlDaysAndNoExpiryAreMutuallyExclusive(): void
    {
        $tester = $this->runCommand(['user' => 'admin@example.test', '--ttl-days' => '7', '--no-expiry' => true]);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertSame([], $this->persisted);
    }

    public function testANonPositiveTtlIsRefused(): void
    {
        foreach (['0', '-1', 'abc', '1.5'] as $ttl) {
            $tester = $this->runCommand(['user' => 'admin@example.test', '--ttl-days' => $ttl]);

            self::assertSame(Command::FAILURE, $tester->getStatusCode(), $ttl);
        }
        self::assertSame([], $this->persisted);
    }

    public function testAnUnknownAdminIsRefused(): void
    {
        $tester = $this->runCommand(['user' => 'nobody@example.test'], adminExists: false);

        self::assertSame(Command::FAILURE, $tester->getStatusCode());
        self::assertSame([], $this->persisted);
    }

    /** @param array<string, string|bool> $input */
    private function runCommand(array $input, bool $adminExists = true): CommandTester
    {
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($this->createStub(EntityRepository::class));
        $entityManager->method('persist')->willReturnCallback(function (object $entity): void {
            if ($entity instanceof McpAccessToken) {
                $this->persisted[] = $entity;
            }
        });

        $admin = $this->createStub(AdminUserInterface::class);
        $admin->method('getId')->willReturn(7);

        /** @var ObjectRepository<AdminUserInterface>&\PHPUnit\Framework\MockObject\Stub $admins */
        $admins = $this->createStub(ObjectRepository::class);
        $admins->method('findOneBy')->willReturn($adminExists ? $admin : null);

        $tester = new CommandTester(new CreateMcpTokenCommand(new AccessTokenManager($entityManager), $admins));
        $tester->execute($input);

        return $tester;
    }

    private function onlyToken(): McpAccessToken
    {
        self::assertCount(1, $this->persisted);

        return $this->persisted[0];
    }
}
