<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Repository;

use League\Bundle\OAuth2ServerBundle\Entity\Client as ClientEntity;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

final class ClientRepository implements ClientRepositoryInterface
{
    /**
     * @var ClientManagerInterface
     */
    private $clientManager;

    private PasswordHasherInterface $hasher;

    public function __construct(ClientManagerInterface $clientManager, PasswordHasherInterface $hasher)
    {
        $this->clientManager = $clientManager;
        $this->hasher = $hasher;
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = $this->clientManager->find($clientIdentifier);

        if (null === $client) {
            return null;
        }

        return $this->buildClientEntity($client);
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $client = $this->clientManager->find($clientIdentifier);

        if (null === $client) {
            return false;
        }

        if (!$client->isActive()) {
            return false;
        }

        if (!$this->isGrantSupported($client, $grantType)) {
            return false;
        }

        if (!$client->isConfidential()) {
            return true;
        }

        $storedSecret = (string) $client->getSecret();
        $inputSecret = (string) $clientSecret;

        // Plain-text migration: stored secret is not a password hash yet.
        // Compare directly and automatically upgrade to a hash on success.
        if (!$this->isHashed($storedSecret)) {
            if (!hash_equals($storedSecret, $inputSecret)) {
                return false;
            }
            $this->rehashAndSave($client, $inputSecret);

            return true;
        }

        // Stored secret is a hash — verify with the hasher.
        if (!$client->verifySecret($inputSecret, $this->hasher)) {
            return false;
        }

        // Automatically rehash if the algorithm or cost settings have changed.
        if ($this->hasher->needsRehash($storedSecret)) {
            $this->rehashAndSave($client, $inputSecret);
        }

        return true;
    }

    private function isHashed(string $secret): bool
    {
        return null !== password_get_info($secret)['algo']
            && 0 !== password_get_info($secret)['algo'];
    }

    private function rehashAndSave(ClientInterface $client, string $plainSecret): void
    {
        $client->setHashedSecret($this->hasher->hash($plainSecret));
        $this->clientManager->save($client);
    }

    private function buildClientEntity(ClientInterface $client): ClientEntity
    {
        $clientEntity = new ClientEntity();
        $clientEntity->setName($client->getName());
        $clientEntity->setIdentifier($client->getIdentifier());
        $clientEntity->setRedirectUri(array_map('strval', $client->getRedirectUris()));
        $clientEntity->setConfidential($client->isConfidential());
        $clientEntity->setAllowPlainTextPkce($client->isPlainTextPkceAllowed());

        return $clientEntity;
    }

    private function isGrantSupported(ClientInterface $client, ?string $grant): bool
    {
        if (null === $grant) {
            return true;
        }

        $grants = $client->getGrants();

        if (empty($grants)) {
            return true;
        }

        return \in_array($grant, $client->getGrants());
    }
}
