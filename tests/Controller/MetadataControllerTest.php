<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Controller;

use Koh\SyliusAgentContracts\Context\AgentContext;
use Koh\SyliusAgentContracts\Context\AgentContextFactoryInterface;
use Koh\SyliusAgentContracts\Http\AgentJsonResponder;
use Koh\SyliusAgentContracts\Model\AuthMethodDescriptor;
use Koh\SyliusAgentContracts\Provider\AuthMethodDescriptorInterface;
use Koh\SyliusAgentContracts\Registry\AuthMethodRegistry;
use Koh\SyliusMcpOAuth\Agent\OAuthAuthMethodDescriptor;
use Koh\SyliusMcpOAuth\Controller\MetadataController;
use PHPUnit\Framework\TestCase;
use Sylius\Component\Core\Model\ChannelInterface;
use Symfony\Component\HttpFoundation\Request;

final class MetadataControllerTest extends TestCase
{
    public function testAuthorizationServerMetadataCarriesTheRfc8414Fields(): void
    {
        $metadata = $this->decode($this->controller()->authorizationServer(new Request()));

        self::assertSame('https://shop.example.com', $metadata['issuer']);
        self::assertSame('https://shop.example.com/admin/mcp/authorize', $metadata['authorization_endpoint']);
        self::assertSame('https://shop.example.com/mcp/oauth/token', $metadata['token_endpoint']);
        self::assertSame('https://shop.example.com/mcp/oauth/register', $metadata['registration_endpoint']);
        self::assertSame('https://shop.example.com/mcp/oauth/revoke', $metadata['revocation_endpoint']);
        self::assertSame(['code'], $metadata['response_types_supported']);
        self::assertSame(['authorization_code'], $metadata['grant_types_supported']);
        self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
        self::assertSame(['none'], $metadata['token_endpoint_auth_methods_supported']);
    }

    /**
     * A client caches this document for maxAge seconds (RFC 8414 does not
     * mandate revalidation), so a wrong value either serves a rotated endpoint
     * long after the change or hammers the server every request.
     */
    public function testDiscoveryDocumentsAreCacheableForFiveMinutes(): void
    {
        $authServer = $this->controller()->authorizationServer(new Request());
        $protectedResource = $this->controller()->protectedResource(new Request());

        self::assertSame(300, $authServer->getMaxAge());
        self::assertSame(300, $protectedResource->getMaxAge());
    }

    /**
     * Absolute URLs come from the channel, not the request.
     *
     * With TLS terminating at an ingress and no trusted_proxies, the request
     * reports the internal host. In an issuer that is not cosmetic: a client
     * comparing it against the issuer it discovered rejects the token.
     */
    public function testIssuerIgnoresTheRequestHost(): void
    {
        $request = Request::create('http://10.0.6.113:8080/.well-known/oauth-authorization-server');

        $metadata = $this->decode($this->controller()->authorizationServer($request));

        self::assertSame('https://shop.example.com', $metadata['issuer']);
        self::assertStringNotContainsString('10.0.6.113', json_encode($metadata, \JSON_THROW_ON_ERROR));
    }

    public function testAgentAuthBlockIsPresent(): void
    {
        $metadata = $this->decode($this->controller()->authorizationServer(new Request()));

        self::assertArrayHasKey('agent_auth', $metadata);
        self::assertSame(
            'https://shop.example.com/mcp/oauth/register',
            $metadata['agent_auth']['register_uri'],
        );
        self::assertSame(['oauth2_access_token'], $metadata['agent_auth']['credential_types_supported']);
        self::assertSame(
            ['oauth_dynamic_client_registration'],
            $metadata['agent_auth']['registration_methods_supported'],
        );
    }

    /**
     * The Auth.md vocabulary is a closed set. "delegated_user" is the literal
     * description but not one of the recognised values, and a scanner then
     * reports "agent_auth metadata was not found" even though the block is
     * complete.
     */
    public function testIdentityTypeUsesTheRecognisedVocabulary(): void
    {
        $metadata = $this->decode($this->controller()->authorizationServer(new Request()));

        self::assertSame(['identity_assertion'], $metadata['agent_auth']['identity_types_supported']);
    }

    /** A shop with several auth methods must advertise all of them. */
    public function testAgentAuthMergesEveryInstalledMethod(): void
    {
        $controller = $this->controller([
            new OAuthAuthMethodDescriptor(),
            $this->staticDescriptor(new AuthMethodDescriptor(
                id: 'web-bot-auth',
                title: 'Web Bot Auth',
                documentation: '',
                identityTypes: ['anonymous'],
                credentialTypes: ['http_message_signature'],
            )),
        ]);

        $agentAuth = $this->decode($controller->authorizationServer(new Request()))['agent_auth'];

        self::assertSame(['oauth2_access_token', 'http_message_signature'], $agentAuth['credential_types_supported']);
        self::assertSame(['identity_assertion', 'anonymous'], $agentAuth['identity_types_supported']);
    }

    public function testProtectedResourceMetadataPointsAtTheMcpEndpoint(): void
    {
        $metadata = $this->decode($this->controller()->protectedResource(new Request()));

        self::assertSame('https://shop.example.com/_mcp', $metadata['resource']);
        self::assertSame(['https://shop.example.com'], $metadata['authorization_servers']);
        self::assertSame(['header'], $metadata['bearer_methods_supported']);
        self::assertSame('https://shop.example.com/auth.md', $metadata['resource_documentation']);
    }

    public function testDiscoveryIsReadableCrossOrigin(): void
    {
        $response = $this->controller()->authorizationServer(new Request());

        self::assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        self::assertTrue($response->headers->hasCacheControlDirective('public'));
    }

    /** @param list<AuthMethodDescriptorInterface>|null $descriptors */
    private function controller(?array $descriptors = null): MetadataController
    {
        return new MetadataController(
            $this->contextFactory(),
            new AuthMethodRegistry($descriptors ?? [new OAuthAuthMethodDescriptor()]),
            new AgentJsonResponder(),
        );
    }

    private function staticDescriptor(AuthMethodDescriptor $descriptor): AuthMethodDescriptorInterface
    {
        return new class($descriptor) implements AuthMethodDescriptorInterface {
            public function __construct(private AuthMethodDescriptor $descriptor)
            {
            }

            public function getAuthMethodDescriptor(AgentContext $context): AuthMethodDescriptor
            {
                return $this->descriptor;
            }
        };
    }

    private function contextFactory(): AgentContextFactoryInterface
    {
        $channel = $this->createMock(ChannelInterface::class);
        $channel->method('getCode')->willReturn('WEB_DE');

        $factory = $this->createMock(AgentContextFactoryInterface::class);
        $factory->method('create')->willReturn(
            new AgentContext($channel, 'https://shop.example.com', 'de_DE', ['de_DE']),
        );

        return $factory;
    }

    /** @return array<string, mixed> */
    private function decode(\Symfony\Component\HttpFoundation\Response $response): array
    {
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) $response->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        return $decoded;
    }
}
