<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use League\Bundle\OAuth2ServerBundle\Manager\InMemory\ClientManager;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\Repository\ClientRepository;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

final class ClientRepositoryTest extends TestCase
{
    private ClientRepository $repository;
    private ClientManager $clientManager;

    protected function setUp(): void
    {
        $this->clientManager = new ClientManager(new EventDispatcher());
        $this->repository = new ClientRepository($this->clientManager, new NativePasswordHasher());
    }

    /**
     * Regression test: a newly created confidential client stores its secret as a bcrypt hash
     * (via the constructor). validateClient() must verify the plain secret against that hash.
     */
    public function testValidateClientSucceedsWithHashedSecretStoredByConstructor(): void
    {
        // The constructor hashes the secret via password_hash($secret, PASSWORD_BCRYPT).
        $client = new Client('My App', 'my-client', 'my-plain-secret');
        $this->clientManager->save($client);

        $this->assertTrue(
            $this->repository->validateClient('my-client', 'my-plain-secret', null)
        );
    }

    public function testValidateClientFailsWithWrongSecret(): void
    {
        $client = new Client('My App', 'my-client', 'my-plain-secret');
        $this->clientManager->save($client);

        $this->assertFalse(
            $this->repository->validateClient('my-client', 'wrong-secret', null)
        );
    }

    public function testValidateClientSucceedsWithPlainTextLegacySecret(): void
    {
        // Simulate a pre-migration client whose secret is stored as plain text.
        $client = new Client('Legacy App', 'legacy-client', 'plain-text-secret');
        // Overwrite the constructor-hashed value with a plain-text secret to simulate
        // a client that was persisted before the hashing migration.
        $client->setHashedSecret('plain-text-secret');
        $this->clientManager->save($client);

        $this->assertTrue(
            $this->repository->validateClient('legacy-client', 'plain-text-secret', null)
        );
    }

    public function testValidateClientReturnsFalseForUnknownClient(): void
    {
        $this->assertFalse(
            $this->repository->validateClient('nonexistent', 'any-secret', null)
        );
    }

    /**
     * Simulates what Doctrine does when hydrating a client from the database:
     * it sets the $secret field directly to the stored hash via reflection,
     * bypassing the constructor. setHashedSecret() replicates this path.
     */
    public function testValidateClientSucceedsWhenSecretSetDirectlyAsHash(): void
    {
        $plainSecret = 'my-plain-secret';
        $hashedSecret = password_hash($plainSecret, \PASSWORD_BCRYPT);

        $client = new Client('My App', 'my-client-db', 'placeholder');
        $client->setHashedSecret($hashedSecret);
        $this->clientManager->save($client);

        $this->assertTrue(
            $this->repository->validateClient('my-client-db', $plainSecret, null)
        );
    }

    public function testValidateClientReturnsFalseForInactiveClient(): void
    {
        $client = (new Client('My App', 'inactive-client', 'secret'))->setActive(false);
        $this->clientManager->save($client);

        $this->assertFalse(
            $this->repository->validateClient('inactive-client', 'secret', null)
        );
    }
}
