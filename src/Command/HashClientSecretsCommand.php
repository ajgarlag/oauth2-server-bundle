<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\Command;

use Doctrine\DBAL\Connection;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

#[AsCommand(name: 'league:oauth2-server:hash-client-secrets', description: 'Hashes existing plain-text client secrets using bcrypt')]
final class HashClientSecretsCommand extends Command
{
    private Connection $connection;
    private string $tablePrefix;
    private PasswordHasherInterface $hasher;

    public function __construct(Connection $connection, string $tablePrefix, PasswordHasherInterface $hasher)
    {
        parent::__construct();

        $this->connection = $connection;
        $this->tablePrefix = $tablePrefix;
        $this->hasher = $hasher;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $table = $this->tablePrefix . 'client';

        $rows = $this->connection->fetchAllAssociative(
            \sprintf('SELECT identifier, secret FROM %s WHERE secret IS NOT NULL', $table)
        );

        $migrated = 0;
        $alreadyHashed = 0;
        $public = 0;

        foreach ($rows as $row) {
            $secret = $row['secret'];

            if ('' === $secret) {
                ++$public;
                continue;
            }

            if (!$this->hasher->needsRehash($secret)) {
                ++$alreadyHashed;
                continue;
            }

            $this->connection->update(
                $table,
                ['secret' => $this->hasher->hash($secret)],
                ['identifier' => $row['identifier']]
            );

            ++$migrated;
        }

        $io->success(\sprintf(
            'Migration complete: %d secret(s) hashed, %d already hashed, %d public client(s) skipped.',
            $migrated,
            $alreadyHashed,
            $public
        ));

        return 0;
    }
}
