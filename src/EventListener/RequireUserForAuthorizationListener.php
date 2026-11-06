<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Exception\InsufficientAuthenticationException;

class RequireUserForAuthorizationListener
{
    public function __construct(
        private readonly Security $security,
    ) {
    }

    public function __invoke(AuthorizationRequestResolveEvent $event): void
    {
        if (null === $user = $this->security->getUser()) {
            throw new InsufficientAuthenticationException('User must be authenticated to resolve authorization request.');
        }

        $event->setUser($user);
    }
}
