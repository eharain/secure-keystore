<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore\Tests;

use PHPUnit\Framework\TestCase;
use TechStyle\SecureKeystore\Keystore;
use TechStyle\SecureKeystore\KeystoreException;
use TechStyle\SecureKeystore\ValueToken;

/**
 * The shared corpus, run against this implementation.
 *
 * The corpus was written by the JavaScript implementation. Nothing here has ever
 * seen that code - this package was written against SPEC.md - so passing this
 * file is the whole cross-language claim, tested rather than asserted.
 *
 * It cannot be a comparison of encoders: every write in this format draws a
 * fresh salt and a fresh IV, so two implementations encrypting the same secret
 * never produce the same bytes. What is pinned is the other direction - these
 * bytes, under this key, must come back as this plaintext - plus the refusals,
 * which matter just as much. An implementation that accepts a tampered token is
 * not conforming however well it handles the happy path.
 */
final class ConformanceTest extends TestCase
{
    /** @var array<string, mixed> */
    private static array $manifest;

    private static string $corpus;

    public static function setUpBeforeClass(): void
    {
        self::$corpus = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'conformance';
        $path = self::$corpus . DIRECTORY_SEPARATOR . 'manifest.json';

        if (!is_file($path)) {
            self::markTestSkipped("no corpus at {$path} - run: node conformance/generate.js");
        }

        self::$manifest = json_decode((string) file_get_contents($path), true);
    }

    private static function fixture(string $relative): string
    {
        return self::$corpus . DIRECTORY_SEPARATOR . 'fixtures' . DIRECTORY_SEPARATOR
            . str_replace('/', DIRECTORY_SEPARATOR, $relative);
    }

    /** Open a corpus keystore without creating anything. */
    private static function reader(string $keystorePath): Keystore
    {
        return new Keystore(self::fixture($keystorePath), 10000, null, false);
    }

    private static function scratch(): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'secure-keystore-' . bin2hex(random_bytes(6));
        mkdir($dir, 0o700, true);

        return $dir;
    }

    private static function removeTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            is_dir($path) ? self::removeTree($path) : @unlink($path);
        }

        @rmdir($dir);
    }

    public function testEveryStoreDecryptsToTheExpectedValues(): void
    {
        self::assertNotEmpty(self::$manifest['stores']);

        foreach (self::$manifest['stores'] as $store) {
            $keystore = self::reader($store['keystorePath']);

            self::assertSame(
                $store['format'],
                $keystore->getStoreInfo($store['name'])['version'],
                $store['name']
            );

            $values = $keystore->getAll(self::$manifest['userKey'], $store['name']);
            self::assertSame($store['expected'], $values, $store['name']);

            // And one at a time, which takes a different path through the code.
            foreach ($store['expected'] as $key => $expected) {
                self::assertSame(
                    $expected,
                    $keystore->get((string) $key, self::$manifest['userKey'], $store['name'])
                );
            }
        }
    }

    public function testEveryTokenDecryptsToTheExpectedValue(): void
    {
        self::assertNotEmpty(self::$manifest['tokens']);

        foreach (self::$manifest['tokens'] as $token) {
            self::assertSame(
                $token['expected'],
                ValueToken::decrypt($token['token'], self::$manifest['userKey']),
                $token['name']
            );

            if ($token['version'] === null) {
                self::assertFalse(ValueToken::isEncryptedValue($token['token']));
            } else {
                self::assertTrue(ValueToken::isEncryptedValue($token['token']));
                self::assertSame($token['version'], ValueToken::tokenVersion($token['token']));
            }
        }
    }

    public function testEveryBundleImportsAndDecrypts(): void
    {
        foreach (self::$manifest['bundles'] as $bundle) {
            $dir = self::scratch();

            try {
                $keystore = new Keystore($dir . DIRECTORY_SEPARATOR . '.keystore', 10000);

                self::assertSame(
                    $bundle['importAs'],
                    $keystore->importStore(self::fixture($bundle['path']), $bundle['importAs'])
                );

                $values = $keystore->getAll(self::$manifest['userKey'], $bundle['importAs']);
                foreach ($bundle['expected'] as $key => $expected) {
                    self::assertSame($expected, $values[$key], $bundle['name']);
                }

                // A hostile bundle must land entirely inside the target store.
                foreach ($bundle['mustNotCreate'] ?? [] as $name) {
                    self::assertFileDoesNotExist($dir . DIRECTORY_SEPARATOR . $name);
                    self::assertFileDoesNotExist(
                        $dir . DIRECTORY_SEPARATOR . '.keystore' . DIRECTORY_SEPARATOR . $name
                    );
                }

                foreach ($bundle['mustCreateInsideStore'] ?? [] as $name) {
                    self::assertFileExists(
                        $dir . DIRECTORY_SEPARATOR . '.keystore' . DIRECTORY_SEPARATOR
                            . $bundle['importAs'] . DIRECTORY_SEPARATOR . $name
                    );
                }
            } finally {
                self::removeTree($dir);
            }
        }
    }

    public function testEveryTokenRefusalIsRefused(): void
    {
        self::assertNotEmpty(self::$manifest['refusals']['tokens']);

        foreach (self::$manifest['refusals']['tokens'] as $refusal) {
            try {
                $value = ValueToken::decrypt($refusal['token'], $refusal['userKey']);
                self::fail("{$refusal['name']} was not refused, returned: " . var_export($value, true));
            } catch (KeystoreException $error) {
                self::assertSame($refusal['code'], $error->getErrorCode(), $refusal['name']);
            }
        }
    }

    public function testEveryBundleRefusalIsRefused(): void
    {
        $dir = self::scratch();

        try {
            $keystore = new Keystore($dir . DIRECTORY_SEPARATOR . '.keystore', 10000);

            foreach (self::$manifest['refusals']['bundles'] as $refusal) {
                try {
                    $keystore->importStore(self::fixture($refusal['path']), 'target');
                    self::fail("{$refusal['name']} was not refused");
                } catch (KeystoreException $error) {
                    self::assertSame($refusal['code'], $error->getErrorCode(), $refusal['name']);
                }
            }
        } finally {
            self::removeTree($dir);
        }
    }

    public function testEveryStoreRefusalIsRefused(): void
    {
        foreach (self::$manifest['refusals']['stores'] as $refusal) {
            try {
                self::reader($refusal['keystorePath'])->getStoreInfo($refusal['store']);
                self::fail("{$refusal['name']} was not refused");
            } catch (KeystoreException $error) {
                self::assertSame($refusal['code'], $error->getErrorCode(), $refusal['name']);
            }
        }
    }

    /**
     * The other direction: a store this package wrote, holding the corpus's own
     * awkward values, read back. The JavaScript, Go and .NET suites do the same,
     * which is what closes the loop.
     */
    public function testWritesAStoreThatReadsBack(): void
    {
        $expected = null;
        foreach (self::$manifest['stores'] as $store) {
            if ($store['name'] === 'basic') {
                $expected = $store['expected'];
                break;
            }
        }

        self::assertNotNull($expected);
        $dir = self::scratch();

        try {
            $keystore = new Keystore(
                $dir . DIRECTORY_SEPARATOR . '.keystore',
                self::$manifest['iterations']
            );

            $input = $dir . DIRECTORY_SEPARATOR . 'php-written.env';
            file_put_contents($input, "master=" . self::$manifest['masterKey'] . "\nplaceholder=x");
            $keystore->secure($input, self::$manifest['userKey'], 'php-written');

            foreach ($expected as $key => $value) {
                $keystore->set((string) $key, (string) $value, self::$manifest['userKey'], 'php-written');
            }
            $keystore->deleteKey('placeholder', 'php-written');

            self::assertSame(
                $expected,
                $keystore->getAll(self::$manifest['userKey'], 'php-written')
            );
        } finally {
            self::removeTree($dir);
        }
    }

    /** A format 2.0 store read, migrated to 3.0, then read again. */
    public function testMigratesALegacyStore(): void
    {
        $legacy = null;
        foreach (self::$manifest['stores'] as $store) {
            if ($store['format'] === '2.0') {
                $legacy = $store;
                break;
            }
        }

        self::assertNotNull($legacy);
        $dir = self::scratch();

        try {
            // Copy the corpus store, so the fixtures are never written to.
            $source = self::fixture($legacy['keystorePath'] . '/' . $legacy['name']);
            $target = $dir . DIRECTORY_SEPARATOR . '.keystore' . DIRECTORY_SEPARATOR . $legacy['name'];
            mkdir($target, 0o700, true);

            foreach (scandir($source) ?: [] as $name) {
                if ($name !== '.' && $name !== '..') {
                    copy($source . DIRECTORY_SEPARATOR . $name, $target . DIRECTORY_SEPARATOR . $name);
                }
            }

            $keystore = new Keystore(
                $dir . DIRECTORY_SEPARATOR . '.keystore',
                self::$manifest['iterations']
            );

            self::assertSame('2.0', $keystore->getStoreInfo($legacy['name'])['version']);
            self::assertFalse($keystore->getStoreInfo($legacy['name'])['current']);

            $result = $keystore->migrate($legacy['name'], self::$manifest['userKey']);
            self::assertSame('2.0', $result['from']);
            self::assertSame('3.0', $result['to']);

            self::assertSame(
                $legacy['expected'],
                $keystore->getAll(self::$manifest['userKey'], $legacy['name'])
            );
            self::assertTrue($keystore->getStoreInfo($legacy['name'])['current']);
        } finally {
            self::removeTree($dir);
        }
    }
}
