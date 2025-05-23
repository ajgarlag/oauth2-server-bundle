<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Model;

use League\Bundle\OAuth2ServerBundle\ValueObject\Scope;

interface AccessTokenInterface
{
    public function __toString(): string;

    public function getIdentifier(): string;

    public function getExpiry(): \DateTimeInterface;

    public function getUserIdentifier(): ?string;

    public function getClient(): ClientInterface;

    /**
     * @return list<Scope>
     */
    public function getScopes(): array;

    public function isRevoked(): bool;

    public function revoke(): self;
}
