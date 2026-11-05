<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Agent;

/**
 * An error of the auth.md registration endpoints (`/agent/identity`,
 * `/agent/identity/claim`), with the profile-specific code from the Errors
 * table of AUTH.md and the HTTP status to send it with.
 */
final class AgentAuthException extends \RuntimeException
{
    public function __construct(
        public readonly string $error,
        string $description,
        public readonly int $status = 400,
    ) {
        parent::__construct($description);
    }
}
