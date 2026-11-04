<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Security;

use Sylius\Component\User\Model\UserInterface as SyliusUserInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Asks whether the administrator behind a token may still act.
 *
 * A token represents a person; when that person's account is switched off in
 * the Sylius admin, their agent must stop too (AUD-011-F01). The check runs
 * the application's own user checker — in a Sylius installation that is
 * `sylius.user_checker.enabled`, the one the admin and API firewalls use — so
 * whatever the application treats as "may not sign in" applies here as well.
 * Without a checker it still refuses a Sylius user whose `isEnabled()` is
 * false: the guard never degrades to "anyone with a token".
 *
 * Used on every bearer request ({@see McpAccessTokenAuthenticator}) and before
 * every token the token endpoint mints, so a disabled administrator can
 * neither use an access token nor refresh one.
 */
final class AccountStatusGuard
{
    public function __construct(
        private readonly ?UserCheckerInterface $userChecker = null,
    ) {
    }

    /**
     * @throws AccountStatusException when the account may not act
     */
    public function check(UserInterface $user): void
    {
        if ($user instanceof SyliusUserInterface && !$user->isEnabled()) {
            $exception = new DisabledException('The MCP token owner is disabled.');
            $exception->setUser($user);

            throw $exception;
        }

        $this->userChecker?->checkPreAuth($user);
    }
}
