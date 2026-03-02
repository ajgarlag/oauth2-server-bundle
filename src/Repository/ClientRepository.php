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

    public function __construct(
        ClientManagerInterface $clientManager,
        private readonly ?PasswordHasherInterface $passwordHasher = null,
    ) {
        $this->clientManager = $clientManager;

        if (null === $this->passwordHasher) {
            trigger_deprecation('league/oauth2-server-bundle', '1.2', 'Not passing a "%s" to "%s" is deprecated since version 1.2 and will be required in 2.0.', PasswordHasherInterface::class, __CLASS__);
        }
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = $this->clientManager->find($clientIdentifier);

        if (null === $client) {
            return null;
        }

        return $this->buildClientEntity($client);
    }

    public function validateClient(string $clientIdentifier, #[\SensitiveParameter] ?string $clientSecret, ?string $grantType): bool
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

        $receivedClientSecret = (string) $clientSecret;
        $storedClientSecret = (string) $client->getSecret();

        if (null === $this->passwordHasher) {
            return hash_equals($storedClientSecret, $receivedClientSecret);
        }

        $secretIsValid = $this->passwordHasher->verify($storedClientSecret, $receivedClientSecret);

        if ($secretIsValid && $this->passwordHasher->needsRehash($storedClientSecret)) {
            if (method_exists($client, 'setSecret')) {
                $client->setSecret($this->passwordHasher->hash($receivedClientSecret));
                $this->clientManager->save($client);
            }
        }

        return $secretIsValid;
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
