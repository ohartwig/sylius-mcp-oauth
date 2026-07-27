<?php

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\OAuth;

/**
 * An OAuth 2.0 protocol error (RFC 6749 §5.2) — carries the machine `error`
 * code the endpoints must return to the client.
 */
final class OAuthException extends \RuntimeException
{
    public function __construct(
        public readonly string $error,
        string $description = '',
    ) {
        parent::__construct($description !== '' ? $description : $error);
    }
}
