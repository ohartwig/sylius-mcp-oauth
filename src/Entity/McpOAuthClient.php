<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * An OAuth client dynamically registered via RFC 7591 (Dynamic Client
 * Registration). MCP clients (Claude Desktop, Cowork, …) register themselves
 * before the authorization flow. We only support PUBLIC clients + PKCE
 * (token_endpoint_auth_method = "none"), so no client secret is stored.
 */
#[ORM\Entity]
#[ORM\Table(name: 'app_mcp_oauth_client')]
/*
 * The unique index is declared here, under the name the migration created,
 * rather than as `unique: true` on the field. Doctrine derives a hashed
 * UNIQ_... name from that flag, so a schema check comparing the mapping
 * against a migrated database reports a RENAME INDEX for it on every run --
 * forever, with nothing actually wrong. Same uniqueness, named where it can be
 * read against the migration that wrote it.
 */
#[ORM\UniqueConstraint(name: 'UNIQ_app_mcp_client_id', columns: ['client_id'])]
class McpOAuthClient
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(name: 'client_id', type: 'string', length: 64)]
    private string $clientId;

    #[ORM\Column(name: 'client_name', type: 'string', length: 191)]
    private string $clientName;

    /** @var list<string> */
    #[ORM\Column(name: 'redirect_uris', type: 'json')]
    private array $redirectUris;

    /** @var list<string> */
    #[ORM\Column(name: 'grant_types', type: 'json')]
    private array $grantTypes;

    #[ORM\Column(name: 'token_endpoint_auth_method', type: 'string', length: 40)]
    private string $tokenEndpointAuthMethod;

    #[ORM\Column(name: 'created_at', type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     */
    public function __construct(
        string $clientId,
        string $clientName,
        array $redirectUris,
        array $grantTypes = ['authorization_code'],
        string $tokenEndpointAuthMethod = 'none',
    ) {
        $this->clientId = $clientId;
        $this->clientName = $clientName;
        $this->redirectUris = $redirectUris;
        $this->grantTypes = $grantTypes;
        $this->tokenEndpointAuthMethod = $tokenEndpointAuthMethod;
        $this->createdAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getClientName(): string
    {
        return $this->clientName;
    }

    /** @return list<string> */
    public function getRedirectUris(): array
    {
        return $this->redirectUris;
    }

    public function hasRedirectUri(string $uri): bool
    {
        return \in_array($uri, $this->redirectUris, true);
    }

    /** @return list<string> */
    public function getGrantTypes(): array
    {
        return $this->grantTypes;
    }

    public function getTokenEndpointAuthMethod(): string
    {
        return $this->tokenEndpointAuthMethod;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }
}
