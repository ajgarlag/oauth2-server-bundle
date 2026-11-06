<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Event;

use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;
use League\Bundle\OAuth2ServerBundle\ValueObject\Scope;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Contracts\EventDispatcher\Event;

final class AuthorizationRequestResolveEvent extends Event
{
    public const AUTHORIZATION_APPROVED = true;
    public const AUTHORIZATION_DENIED = false;

    private bool $authorizationResolution = self::AUTHORIZATION_DENIED;

    private ?Response $response = null;

    /**
     * @param Scope[] $scopes
     */
    public function __construct(
        private readonly AuthorizationRequestInterface $authorizationRequest,
        private readonly array $scopes,
        private readonly ClientInterface $client,
        private ?UserInterface $user,
    ) {
    }

    public function getAuthorizationResolution(): bool
    {
        return $this->authorizationResolution;
    }

    public function resolveAuthorization(bool $authorizationResolution): self
    {
        $this->authorizationResolution = $authorizationResolution;
        $this->response = null;
        $this->stopPropagation();

        return $this;
    }

    public function getResponse(): ?Response
    {
        return $this->response;
    }

    public function setResponse(Response $response): self
    {
        $this->response = $response;
        $this->stopPropagation();

        return $this;
    }

    public function getGrantTypeId(): string
    {
        return $this->authorizationRequest->getGrantTypeId();
    }

    public function getClient(): ClientInterface
    {
        return $this->client;
    }

    public function getUser(): UserInterface
    {
        if (null === $this->user) {
            trigger_deprecation(
                'league/oauth2-server-bundle',
                '2.1',
                'Accessing the user when it is not set will return null in 3.0.'
            );

            return new class implements UserInterface {
                public function getRoles(): array
                {
                    return [];
                }

                public function getPassword(): null
                {
                    return null;
                }

                public function getSalt(): null
                {
                    return null;
                }

                public function getUserIdentifier(): string
                {
                    return 'anonymous-league-oauth2-server-user';
                }

                public function eraseCredentials(): void
                {
                }
            };
        }

        return $this->user;
    }

    public function setUser(UserInterface $user): self
    {
        $this->user = $user;

        return $this;
    }

    /**
     * @return Scope[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function isAuthorizationApproved(): bool
    {
        return $this->authorizationRequest->isAuthorizationApproved();
    }

    public function getRedirectUri(): ?string
    {
        return $this->authorizationRequest->getRedirectUri();
    }

    public function getState(): ?string
    {
        return $this->authorizationRequest->getState();
    }

    public function getCodeChallenge(): ?string
    {
        return $this->authorizationRequest->getCodeChallenge();
    }

    public function getCodeChallengeMethod(): ?string
    {
        return $this->authorizationRequest->getCodeChallengeMethod();
    }
}
