<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Command;

use Koh\SyliusMcpOAuth\OAuth\AccessTokenManager;
use Doctrine\Persistence\ObjectRepository;
use Sylius\Component\Core\Model\AdminUserInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Mints an MCP access token for an admin user, for headless and service
 * integrations that cannot run the browser OAuth flow. The raw token is printed
 * once.
 *
 * A CLI token expires after {@see DEFAULT_TTL_DAYS} days unless `--ttl-days`
 * says otherwise. A token that never expires needs `--no-expiry`, spelled out:
 * a bearer credential that outlives everyone's memory of it is the one nobody
 * revokes (THR-AGENT-020).
 */
#[AsCommand(
    name: 'mcp:token:create',
    description: 'Create an MCP access token bound to a Sylius admin user (shown once).',
)]
final class CreateMcpTokenCommand extends Command
{
    public const DEFAULT_TTL_DAYS = 90;

    /** @param ObjectRepository<AdminUserInterface> $adminUsers */
    public function __construct(
        private readonly AccessTokenManager $tokens,
        #[Autowire(service: 'sylius.repository.admin_user')]
        private readonly ObjectRepository $adminUsers,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addArgument('user', InputArgument::REQUIRED, 'Admin user email or username')
            ->addOption('name', null, InputOption::VALUE_REQUIRED, 'Token label', 'CLI token')
            ->addOption('ttl-days', null, InputOption::VALUE_REQUIRED, \sprintf('Expiry in days (default: %d)', self::DEFAULT_TTL_DAYS))
            ->addOption('no-expiry', null, InputOption::VALUE_NONE, 'Create a token that never expires (explicit opt-in)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $identifier = (string) $input->getArgument('user');
        $admin = $this->adminUsers->findOneBy(['email' => $identifier])
            ?? $this->adminUsers->findOneBy(['username' => $identifier]);

        if ($admin === null) {
            $io->error(sprintf('No admin user found for "%s".', $identifier));

            return Command::FAILURE;
        }

        $ttlDays = $input->getOption('ttl-days');
        $noExpiry = (bool) $input->getOption('no-expiry');

        if ($noExpiry && null !== $ttlDays) {
            $io->error('--ttl-days and --no-expiry are mutually exclusive.');

            return Command::FAILURE;
        }

        $expiresAt = null;
        if (!$noExpiry) {
            $days = self::DEFAULT_TTL_DAYS;
            if (null !== $ttlDays) {
                if (!ctype_digit((string) $ttlDays) || (int) $ttlDays < 1) {
                    $io->error('--ttl-days must be a positive integer.');

                    return Command::FAILURE;
                }
                $days = (int) $ttlDays;
            }
            $expiresAt = (new \DateTimeImmutable())->modify(\sprintf('+%d days', $days));
        }

        $result = $this->tokens->create(
            adminUserId: (int) $admin->getId(),
            name: (string) $input->getOption('name'),
            expiresAt: $expiresAt,
        );

        $io->success('MCP access token created.');
        $io->writeln('Copy it now — it is not stored and cannot be shown again:');
        $io->writeln('');
        $io->writeln('  <info>' . $result['token'] . '</info>');
        $io->writeln('');
        $io->writeln(sprintf(
            'Owner: %s | Expires: %s',
            $identifier,
            $expiresAt?->format('Y-m-d H:i') ?? 'never',
        ));
        $io->writeln('Use it as: Authorization: Bearer <token>  against POST /_mcp');

        return Command::SUCCESS;
    }
}
