<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Migrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * koh/sylius-mcp-oauth 3.2: auth.md agent registrations and their claim
 * ceremony.
 *
 * No foreign key to sylius_admin_user: a registration exists before any
 * administrator claims it, and the token endpoint re-checks the claiming
 * administrator on every exchange.
 */
final class Version20261105120000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'koh/sylius-mcp-oauth: auth.md agent registrations';
    }

    public function up(Schema $schema): void
    {
        $this->addSql(<<<'SQL'
            CREATE TABLE app_mcp_agent_registration (
                id INT AUTO_INCREMENT NOT NULL,
                registration_id VARCHAR(64) NOT NULL,
                type VARCHAR(20) NOT NULL,
                claim_token_hash VARCHAR(64) NOT NULL,
                claim_expires_at DATETIME NOT NULL COMMENT '(DC2Type:datetime_immutable)',
                claim_email VARCHAR(191) DEFAULT NULL,
                attempt_id VARCHAR(64) DEFAULT NULL,
                attempt_token_hash VARCHAR(64) DEFAULT NULL,
                user_code_hash VARCHAR(64) DEFAULT NULL,
                user_code_expires_at DATETIME DEFAULT NULL COMMENT '(DC2Type:datetime_immutable)',
                failed_code_attempts INT NOT NULL,
                last_polled_at DATETIME DEFAULT NULL COMMENT '(DC2Type:datetime_immutable)',
                admin_user_id INT DEFAULT NULL,
                scopes JSON NOT NULL,
                claimed_at DATETIME DEFAULT NULL COMMENT '(DC2Type:datetime_immutable)',
                claim_redeemed_at DATETIME DEFAULT NULL COMMENT '(DC2Type:datetime_immutable)',
                revoked TINYINT(1) NOT NULL,
                created_at DATETIME NOT NULL COMMENT '(DC2Type:datetime_immutable)',
                created_ip VARCHAR(45) DEFAULT NULL,
                UNIQUE INDEX UNIQ_app_mcp_agent_reg_id (registration_id),
                UNIQUE INDEX UNIQ_app_mcp_agent_reg_claim (claim_token_hash),
                INDEX idx_mcp_agent_reg_attempt (attempt_token_hash),
                PRIMARY KEY(id)
            ) DEFAULT CHARACTER SET utf8mb4 COLLATE `utf8mb4_unicode_ci` ENGINE = InnoDB
        SQL);
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP TABLE app_mcp_agent_registration');
    }
}
