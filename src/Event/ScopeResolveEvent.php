<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Event;

use League\Bundle\OAuth2ServerBundle\Model\AbstractClient;
use League\Bundle\OAuth2ServerBundle\ValueObject\Grant;
use League\Bundle\OAuth2ServerBundle\ValueObject\Scope;
use Symfony\Contracts\EventDispatcher\Event;

final class ScopeResolveEvent extends Event
{
    /**
     * @var list<Scope>
     */
    private $scopes;

    /**
     * @var Grant
     */
    private $grant;

    /**
     * @var AbstractClient
     */
    private $client;

    /**
     * @var string|int|null
     */
    private $userIdentifier;

    /**
     * @param list<Scope> $scopes
     */
    public function __construct(array $scopes, Grant $grant, AbstractClient $client, string|int|null $userIdentifier)
    {
        $this->scopes = $scopes;
        $this->grant = $grant;
        $this->client = $client;
        $this->userIdentifier = $userIdentifier;
    }

    /**
     * @return list<Scope>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function setScopes(Scope ...$scopes): self
    {
        /** @var list<Scope> $scopes */
        $this->scopes = $scopes;

        return $this;
    }

    public function getGrant(): Grant
    {
        return $this->grant;
    }

    public function getClient(): AbstractClient
    {
        return $this->client;
    }

    public function getUserIdentifier(): string|int|null
    {
        return $this->userIdentifier;
    }
}
