<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Tests\Unit;

use League\Bundle\OAuth2ServerBundle\Model\Client;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\Hasher\NativePasswordHasher;

final class ClientEntityTest extends TestCase
{
    /**
     * @dataProvider confidentialDataProvider
     */
    public function testClientConfidentiality(?string $secret, bool $isConfidential): void
    {
        $client = new Client('name', 'identifier', $secret);

        $this->assertSame($isConfidential, $client->isConfidential());
    }

    public function confidentialDataProvider(): iterable
    {
        return [
            'Client with null secret is not confidential' => [null, false],
            'Client with empty secret is not confidential' => ['', false],
            'Client with non empty secret is confidential' => ['f', true],
        ];
    }

    public function testVerifySecretWithCorrectSecret(): void
    {
        $hasher = new NativePasswordHasher();
        $client = new Client('name', 'identifier', $hasher->hash('my-secret'));

        $this->assertTrue($client->verifySecret('my-secret', $hasher));
    }

    public function testVerifySecretWithWrongSecret(): void
    {
        $hasher = new NativePasswordHasher();
        $client = new Client('name', 'identifier', $hasher->hash('my-secret'));

        $this->assertFalse($client->verifySecret('wrong-secret', $hasher));
    }

    public function testVerifySecretOnPublicClient(): void
    {
        $hasher = new NativePasswordHasher();
        $client = new Client('name', 'identifier', null);

        $this->assertFalse($client->verifySecret('any-secret', $hasher));
    }

    public function testConstructorStoresSecretAsIs(): void
    {
        // The constructor no longer hashes — hashing is the responsibility of the
        // service layer (e.g. CreateClientCommand) so that the same hasher is used
        // for both creation and verification.
        $client = new Client('name', 'identifier', 'my-secret');

        $this->assertSame('my-secret', $client->getSecret());
    }
}
