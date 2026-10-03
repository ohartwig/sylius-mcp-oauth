<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * koh/sylius-mcp-oauth 3.0: audience binding (RFC 8707), refresh-token
 * rotation, and the client address per token.
 *
 * The three original tables were created by the consuming application's own
 * migrations, from the time these classes lived there. This is the first
 * migration the bundle ships itself; it only adds to those tables.
 */
final class Version20261003120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'koh/sylius-mcp-oauth: token audience, refresh tokens, token IPs';
    }

    public function up(Schema $schema): void
    {
        $this->addSql(<<<'SQL'
            ALTER TABLE app_mcp_access_token
                ADD audience VARCHAR(512) DEFAULT NULL,
                ADD refresh_family VARCHAR(64) DEFAULT NULL,
                ADD created_ip VARCHAR(45) DEFAULT NULL,
                ADD last_used_ip VARCHAR(45) DEFAULT NULL,
                ADD INDEX idx_mcp_token_family (refresh_family)
        SQL);

        $this->addSql('ALTER TABLE app_mcp_authorization_code ADD resource VARCHAR(512) DEFAULT NULL');

        $this->addSql(<<<'SQL'
            CREATE TABLE app_mcp_refresh_token (
                id INT AUTO_INCREMENT NOT NULL,
                token_hash VARCHAR(64) NOT NULL,
                family VARCHAR(64) NOT NULL,
                admin_user_id INT NOT NULL,
                client_id VARCHAR(191) NOT NULL,
                scopes JSON NOT NULL,
                audience VARCHAR(512) DEFAULT NULL,
                expires_at DATETIME NOT NULL COMMENT '(DC2Type:datetime_immutable)',
                created_at DATETIME NOT NULL COMMENT '(DC2Type:datetime_immutable)',
                used_at DATETIME DEFAULT NULL COMMENT '(DC2Type:datetime_immutable)',
                revoked TINYINT(1) NOT NULL,
                UNIQUE INDEX UNIQ_app_mcp_refresh_hash (token_hash),
                INDEX idx_mcp_refresh_family (family),
                INDEX idx_mcp_refresh_admin (admin_user_id),
                PRIMARY KEY(id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
        SQL);

        // Same rule as for access tokens: an admin who is deleted takes
        // their tokens along.
        $this->addSql(<<<'SQL'
            ALTER TABLE app_mcp_refresh_token
                ADD CONSTRAINT FK_app_mcp_refresh_admin
                FOREIGN KEY (admin_user_id) REFERENCES sylius_admin_user (id)
                ON DELETE CASCADE
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE app_mcp_refresh_token');
        $this->addSql('ALTER TABLE app_mcp_authorization_code DROP resource');
        $this->addSql(<<<'SQL'
            ALTER TABLE app_mcp_access_token
                DROP INDEX idx_mcp_token_family,
                DROP audience,
                DROP refresh_family,
                DROP created_ip,
                DROP last_used_ip
        SQL);
    }
}
