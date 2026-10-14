<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Integration;

use League\Bundle\OAuth2ServerBundle\Converter\ScopeConverter;
use League\Bundle\OAuth2ServerBundle\Entity\DeviceCode as DeviceCodeEntity;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\Model\DeviceCode;
use League\Bundle\OAuth2ServerBundle\Model\DeviceCodeInterface;
use League\Bundle\OAuth2ServerBundle\Repository\ClientRepository;
use League\Bundle\OAuth2ServerBundle\Repository\DeviceCodeRepository;
use Symfony\Bridge\PhpUnit\ExpectDeprecationTrait;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

final class DeviceCodeRepositoryTest extends AbstractIntegrationTest
{
    use ExpectDeprecationTrait;

    public function testDeviceCodeRevoking(): void
    {
        $identifier = 'foo';

        $deviceCode = new DeviceCode(
            $identifier,
            new \DateTimeImmutable('+1 day'),
            new Client('name', 'identifier', 'secret'),
            null,
            [],
            '',
            false,
            '',
            null,
            5
        );

        $this->deviceCodeManager->save($deviceCode);

        $this->assertSame($deviceCode, $this->deviceCodeManager->find($identifier));

        $deviceCodeRepository = new DeviceCodeRepository(
            $this->deviceCodeManager, $this->clientManager, new ScopeConverter(), new ClientRepository($this->clientManager, new NativePasswordHasher())
        );

        $deviceCodeRepository->revokeDeviceCode($identifier);

        $this->assertTrue($deviceCode->isRevoked());
        $this->assertSame($deviceCode, $this->deviceCodeManager->find($identifier));
    }

    public function testVerificationUriCompleteSettingIsPersisted(): void
    {
        $client = new Client('name', 'identifier', 'secret');
        $this->clientManager->save($client);

        $clientRepository = new ClientRepository($this->clientManager, new NativePasswordHasher());
        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setIdentifier('foo');
        $deviceCodeEntity->setExpiryDateTime(new \DateTimeImmutable('+1 day'));
        $clientEntity = $clientRepository->getClientEntity('identifier');
        $this->assertNotNull($clientEntity);
        $deviceCodeEntity->setClient($clientEntity);
        $deviceCodeEntity->setUserCode('ABCD');
        $deviceCodeEntity->setVerificationUri('https://example.com/device');
        $deviceCodeEntity->setVerificationUriCompleteInAuthResponse(true);

        $deviceCodeRepository = new DeviceCodeRepository(
            $this->deviceCodeManager,
            $this->clientManager,
            new ScopeConverter(),
            $clientRepository,
        );

        $deviceCodeRepository->persistDeviceCode($deviceCodeEntity);

        $deviceCode = $this->deviceCodeManager->find('foo');
        $this->assertNotNull($deviceCode);
        $this->assertTrue($deviceCode->getIncludeVerificationUriComplete());

        $deviceCodeEntity->setVerificationUriCompleteInAuthResponse(false);
        $deviceCodeRepository->persistDeviceCode($deviceCodeEntity);

        $this->assertFalse($deviceCode->getIncludeVerificationUriComplete());
    }

    /**
     * @group legacy
     */
    public function testPersistingDeviceCodeWithoutSetterTriggersDeprecation(): void
    {
        $legacyDeviceCode = $this->createMock(DeviceCodeInterface::class);
        $legacyDeviceCode->method('getIdentifier')->willReturn('foo');
        $legacyDeviceCode->method('getLastPolledAt')->willReturn(null);
        $legacyDeviceCode->method('getUserIdentifier')->willReturn(null);
        $this->deviceCodeManager->save($legacyDeviceCode);

        $deviceCodeEntity = new DeviceCodeEntity();
        $deviceCodeEntity->setIdentifier('foo');
        $deviceCodeEntity->setVerificationUriCompleteInAuthResponse(true);

        $deviceCodeRepository = new DeviceCodeRepository(
            $this->deviceCodeManager,
            $this->clientManager,
            new ScopeConverter(),
            new ClientRepository($this->clientManager, new NativePasswordHasher()),
        );

        $this->expectDeprecation('Since league/oauth2-server-bundle 1.2: Not implementing method "setIncludeVerificationUriComplete()" in device code "%s" is deprecated. This method will be required in 2.0.');

        $deviceCodeRepository->persistDeviceCode($deviceCodeEntity);
    }
}
