<?php

declare(strict_types=1);

namespace League\Bundle\OAuth2ServerBundle\DBAL\Type;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\TextType;

/**
 * @template T
 */
abstract class ImplodedArray extends TextType
{
    /**
     * @var string
     */
    private const VALUE_DELIMITER = ' ';

    public function convertToDatabaseValue(mixed $value, AbstractPlatform $platform): ?string
    {
        if (!\is_array($value)) {
            throw new \LogicException('This type can only be used in combination with arrays.');
        }

        if (0 === \count($value)) {
            return null;
        }

        foreach ($value as $item) {
            $this->assertValueCanBeImploded($item);
        }

        return implode(self::VALUE_DELIMITER, $value);
    }

    /**
     * @return list<T>
     */
    public function convertToPHPValue(mixed $value, AbstractPlatform $platform): array
    {
        if (null === $value) {
            return [];
        }

        \assert(\is_string($value), 'Expected $value of be either a string or null.');

        /** @var list<non-empty-string> $values */
        $values = explode(self::VALUE_DELIMITER, $value);

        return $this->convertDatabaseValues($values);
    }

    public function getSQLDeclaration(array $column, AbstractPlatform $platform): string
    {
        $column['length'] = 65535;

        return parent::getSQLDeclaration($column, $platform);
    }

    public function requiresSQLCommentHint(AbstractPlatform $platform): bool
    {
        return true;
    }

    /**
     * @param T $value
     */
    private function assertValueCanBeImploded($value): void
    {
        if (null === $value) {
            return;
        }

        if (\is_scalar($value)) {
            return;
        }

        if (\is_object($value) && method_exists($value, '__toString')) {
            return;
        }

        throw new \InvalidArgumentException(\sprintf('The value of \'%s\' type cannot be imploded.', \gettype($value)));
    }

    /**
     * @param list<non-empty-string> $values
     *
     * @return list<T>
     */
    abstract protected function convertDatabaseValues(array $values): array;
}
