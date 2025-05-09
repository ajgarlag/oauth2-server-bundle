<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Fixtures;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class SecurityTestController extends AbstractController
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    public function __construct(TokenStorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    public function helloAction(): Response
    {
        /** @var UserInterface $user */
        $user = $this->getUser();

        return new Response(
            \sprintf('Hello, %s', null === $user || $user instanceof ClientCredentialsUser ? 'guest' : $user->getUserIdentifier())
        );
    }

    public function scopeAction(): Response
    {
        return new Response('Only certain scopes should be able to access this action.');
    }

    public function rolesAction(): Response
    {
        $roles = $this->tokenStorage->getToken()->getRoleNames();

        return new Response(
            \sprintf(
                'These are the roles I have currently assigned: %s',
                implode(', ', $roles)
            )
        );
    }

    public function authorizationAction(): Response
    {
        $this->denyAccessUnlessGranted('ROLE_OAUTH2_FANCY');

        return new Response('access granted');
    }
}
