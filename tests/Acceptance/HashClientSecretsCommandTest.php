<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Acceptance;

use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Tester\CommandTester;

final class HashClientSecretsCommandTest extends AbstractAcceptanceTest
{
    public function testHashPlainTextSecrets(): void
    {
        $connection = $this->getConnection();

        $this->insertClientWithPlainSecret($connection, 'client-plain', 'plain-text-secret');

        $commandTester = $this->runCommand();

        $this->assertSame(0, $commandTester->getStatusCode());
        $this->assertStringContainsString('1 secret(s) hashed', $commandTester->getDisplay());

        $hashedSecret = $connection->fetchOne('SELECT secret FROM oauth2_client WHERE identifier = ?', ['client-plain']);
        $this->assertStringStartsWith('$2y$', $hashedSecret);
        $this->assertTrue(password_verify('plain-text-secret', $hashedSecret));
    }

    public function testSkipAlreadyHashedSecrets(): void
    {
        $connection = $this->getConnection();

        $bcryptHash = password_hash('already-hashed', \PASSWORD_BCRYPT);
        $this->insertClientWithPlainSecret($connection, 'client-hashed', $bcryptHash);

        $commandTester = $this->runCommand();

        $this->assertSame(0, $commandTester->getStatusCode());
        $this->assertStringContainsString('0 secret(s) hashed', $commandTester->getDisplay());
        $this->assertStringContainsString('1 already hashed', $commandTester->getDisplay());

        $storedSecret = $connection->fetchOne('SELECT secret FROM oauth2_client WHERE identifier = ?', ['client-hashed']);
        $this->assertSame($bcryptHash, $storedSecret);
    }

    public function testSkipPublicClients(): void
    {
        $connection = $this->getConnection();

        $connection->insert('oauth2_client', [
            'identifier' => 'client-public',
            'name' => 'Public Client',
            'secret' => null,
            'active' => 1,
            'allowPlainTextPkce' => 0,
        ]);

        $commandTester = $this->runCommand();

        $this->assertSame(0, $commandTester->getStatusCode());
        $this->assertStringContainsString('0 secret(s) hashed', $commandTester->getDisplay());
    }

    public function testMixedClients(): void
    {
        $connection = $this->getConnection();

        $this->insertClientWithPlainSecret($connection, 'plain-1', 'secret-one');
        $this->insertClientWithPlainSecret($connection, 'plain-2', 'secret-two');

        $bcryptHash = password_hash('hashed-secret', \PASSWORD_BCRYPT);
        $this->insertClientWithPlainSecret($connection, 'already-hashed', $bcryptHash);

        $connection->insert('oauth2_client', [
            'identifier' => 'public-client',
            'name' => 'Public',
            'secret' => null,
            'active' => 1,
            'allowPlainTextPkce' => 0,
        ]);

        $commandTester = $this->runCommand();

        $this->assertStringContainsString('2 secret(s) hashed', $commandTester->getDisplay());
        $this->assertStringContainsString('1 already hashed', $commandTester->getDisplay());

        $this->assertTrue(password_verify('secret-one', $connection->fetchOne(
            'SELECT secret FROM oauth2_client WHERE identifier = ?',
            ['plain-1']
        )));
        $this->assertTrue(password_verify('secret-two', $connection->fetchOne(
            'SELECT secret FROM oauth2_client WHERE identifier = ?',
            ['plain-2']
        )));
    }

    private function getConnection(): Connection
    {
        return $this->client->getContainer()->get('database_connection');
    }

    private function insertClientWithPlainSecret(Connection $connection, string $identifier, string $secret): void
    {
        $connection->insert('oauth2_client', [
            'identifier' => $identifier,
            'name' => 'Test Client',
            'secret' => $secret,
            'active' => 1,
            'allowPlainTextPkce' => 0,
        ]);
    }

    private function runCommand(): CommandTester
    {
        $command = $this->application->find('league:oauth2-server:hash-client-secrets');
        $commandTester = new CommandTester($command);
        $commandTester->execute([]);

        return $commandTester;
    }
}
