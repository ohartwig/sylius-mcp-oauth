<?php

// SPDX-FileCopyrightText: 2026 Kai Ole Hartwig <mail@ole-hartwig.eu>
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace Koh\SyliusMcpOAuth\Tests\Agent;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use Koh\SyliusMcpOAuth\Entity\McpAgentRegistration;
use PHPUnit\Framework\TestCase;

/**
 * An in-memory stand-in for the registration table: persist() stores,
 * findOneBy() matches on entity properties, and the conditional UPDATE that
 * spends a claim token succeeds once per registration — as the database would,
 * and like the database without changing the entity already loaded.
 */
final class RegistrationStore
{
    /** @var list<McpAgentRegistration> */
    public array $rows = [];

    public int $flushes = 0;

    /** Set to simulate a concurrent request that spent the claim token first. */
    public bool $loseTheRace = false;

    /** @var array<int, true> ids the UPDATE has spent; like the database, it does not touch the loaded entity */
    private array $redeemed = [];

    public function entityManager(TestCase $test): EntityManagerInterface
    {
        $repository = (new \ReflectionMethod($test, 'createStub'))->invoke($test, EntityRepository::class);
        $repository->method('findOneBy')->willReturnCallback(fn (array $criteria): ?McpAgentRegistration => $this->find($criteria));

        $parameters = [];
        $query = (new \ReflectionMethod($test, 'createStub'))->invoke($test, Query::class);
        $query->method('setParameter')->willReturnCallback(static function (string $key, mixed $value) use (&$parameters, &$query) {
            $parameters[$key] = $value;

            return $query;
        });
        $query->method('execute')->willReturnCallback(function () use (&$parameters): int {
            $id = $parameters['id'] ?? null;
            if ($this->loseTheRace || !\is_int($id) || isset($this->redeemed[$id]) || !$parameters['now'] instanceof \DateTimeImmutable) {
                return 0;
            }
            $this->redeemed[$id] = true;

            return 1;
        });

        $entityManager = (new \ReflectionMethod($test, 'createStub'))->invoke($test, EntityManagerInterface::class);
        $entityManager->method('getRepository')->willReturn($repository);
        $entityManager->method('createQuery')->willReturn($query);
        $entityManager->method('persist')->willReturnCallback(function (object $entity): void {
            \assert($entity instanceof McpAgentRegistration);
            (new \ReflectionProperty(McpAgentRegistration::class, 'id'))->setValue($entity, \count($this->rows) + 1);
            $this->rows[] = $entity;
        });
        $entityManager->method('flush')->willReturnCallback(function (): void {
            ++$this->flushes;
        });

        return $entityManager;
    }

    /** @param array<string, mixed> $criteria */
    private function find(array $criteria): ?McpAgentRegistration
    {
        foreach ($this->rows as $row) {
            foreach ($criteria as $property => $value) {
                if ((new \ReflectionProperty(McpAgentRegistration::class, $property))->getValue($row) !== $value) {
                    continue 2;
                }
            }

            return $row;
        }

        return null;
    }
}
