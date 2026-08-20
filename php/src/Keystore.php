<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * The store: a directory, and the operations on it.
 *
 * Two layers of encryption, and it is worth being precise about what the second
 * one buys. A user key unlocks the master key; the master key unlocks each
 * value. That is not defence in depth against a leaked user key - anyone holding
 * the user key reaches everything - it is what lets every value carry its own
 * salt and its own derived key, so no two values on disk share any material and
 * re-keying one value touches one file.
 *
 * The on-disk format is specified in SPEC.md at the root of the repository. This
 * build writes format 3.0 and reads 3.0 and 2.0. A store is never half one and
 * half the other: writing to a 2.0 store keeps writing 2.0 records until
 * migrate() moves the whole thing across.
 */
final class Keystore
{
    private const JSON_WRITE = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    private string $keystoreDir;
    private int $iterations;

    /** @var callable(string): void|null */
    private $logger;

    /**
     * @param string|null $keystoreDir where stores live. Default ./.keystore.
     * @param int $iterations the PBKDF2 count the *user key* is stretched with,
     *     for new and migrated stores. Recorded in the store, so raising it
     *     never orphans one written before. It does not apply to value keys,
     *     which are derived with HKDF and take no count.
     * @param callable(string): void|null $logger called with one line of
     *     progress. Null means the package prints nothing at all, which is the
     *     default and what a server wants.
     * @param bool $createDir create the keystore directory if it is absent.
     */
    public function __construct(
        ?string $keystoreDir = null,
        int $iterations = Format::DEFAULT_ITERATIONS,
        ?callable $logger = null,
        bool $createDir = true
    ) {
        if ($iterations < Format::MIN_ITERATIONS) {
            throw new KeystoreException(
                ErrorCodes::INVALID_OPTIONS,
                'iterations must be at least ' . Format::MIN_ITERATIONS . ", not {$iterations}"
            );
        }

        $this->keystoreDir = $keystoreDir ?? (getcwd() . DIRECTORY_SEPARATOR . Format::DEFAULT_KEYSTORE_DIRNAME);
        $this->iterations = $iterations;
        $this->logger = $logger;

        if ($createDir && !is_dir($this->keystoreDir)) {
            @mkdir($this->keystoreDir, 0o700, true);
        }
    }

    public function dir(): string
    {
        return $this->keystoreDir;
    }

    public function iterations(): int
    {
        return $this->iterations;
    }

    private function log(string $message): void
    {
        if ($this->logger !== null) {
            ($this->logger)($message);
        }
    }

    private function storeDir(string $storeName): string
    {
        return $this->keystoreDir . DIRECTORY_SEPARATOR . $storeName;
    }

    /**
     * An ISO 8601 stamp in the shape every implementation writes.
     *
     * The time is sampled once and both halves come from that sample. Reading the
     * clock twice - once for the date and once for the milliseconds - gives a
     * stamp that disagrees with itself when the two land either side of a second
     * boundary, which is rare, wrong, and very hard to reproduce.
     */
    private static function now(): string
    {
        $time = microtime(true);
        $seconds = (int) floor($time);
        $milliseconds = (int) floor(($time - $seconds) * 1000);

        return gmdate('Y-m-d\TH:i:s', $seconds) . sprintf('.%03dZ', $milliseconds);
    }

    /**
     * Read and parse a store's master.json, or say which of the two is missing.
     *
     * The whole document is kept, not just the fields this build knows about, so
     * a store written by a newer implementation is not silently downgraded by an
     * older one that happens to write to it.
     *
     * @return array<string, mixed>
     */
    private function readMetadata(string $storeName): array
    {
        $dir = $this->storeDir($storeName);
        if (!is_dir($dir)) {
            throw new KeystoreException(ErrorCodes::STORE_NOT_FOUND, "keystore \"{$storeName}\" not found");
        }

        $masterPath = $dir . DIRECTORY_SEPARATOR . Format::MASTER_FILE;
        if (!is_file($masterPath)) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "keystore \"{$storeName}\" has no " . Format::MASTER_FILE
                    . ' - the directory exists but is not a store'
            );
        }

        $metadata = json_decode((string) file_get_contents($masterPath), true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($metadata)) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                Format::MASTER_FILE . " in keystore \"{$storeName}\" is not readable JSON"
            );
        }

        $version = self::formatOf($metadata);
        if (Format::majorOf($version) > Format::majorOf(Format::STORE_VERSION)) {
            throw new KeystoreException(
                ErrorCodes::UNSUPPORTED_FORMAT,
                "keystore \"{$storeName}\" is in format {$version}, and this build reads up to "
                    . Format::STORE_VERSION
            );
        }

        return $metadata;
    }

    /** @param array<string, mixed> $metadata */
    private function writeMetadata(string $storeName, array $metadata): void
    {
        $metadata['updated'] = self::now();

        file_put_contents(
            $this->storeDir($storeName) . DIRECTORY_SEPARATOR . Format::MASTER_FILE,
            (string) json_encode($metadata, self::JSON_WRITE)
        );
    }

    /**
     * The store format a metadata document is in. Absent means 1.0, which is the
     * same on-disk shape as 2.0 - 2.0 only added optional fields.
     *
     * @param array<string, mixed> $metadata
     */
    private static function formatOf(array $metadata): string
    {
        $version = $metadata['version'] ?? null;

        return is_string($version) && $version !== '' ? $version : '1.0';
    }

    /** @param array<string, mixed> $metadata */
    private static function isLegacy(array $metadata): bool
    {
        return Format::majorOf(self::formatOf($metadata)) < 3;
    }

    /**
     * The count a store was written with. Absent means it predates the field,
     * and every version that did so used 100,000.
     *
     * @param array<string, mixed> $record
     */
    private static function iterationsOf(array $record): int
    {
        $count = $record['iterations'] ?? null;

        return is_int($count) ? $count : Format::LEGACY_ITERATIONS;
    }

    /** @param array<string, mixed> $metadata */
    private static function ivLengthOf(array $metadata): int
    {
        return self::isLegacy($metadata) ? Format::IV_LENGTH_LEGACY : Format::IV_LENGTH;
    }

    /** @param array<string, mixed> $metadata */
    private static function valueAad(array $metadata, string $keyName): string
    {
        return self::isLegacy($metadata) ? '' : Format::valueContext($keyName);
    }

    /**
     * Stretch the user key and decrypt the store's master key.
     *
     * @param array<string, mixed> $metadata
     */
    private function unlockMaster(array $metadata, string $userKey, string $storeName): string
    {
        if ($userKey === '') {
            throw new KeystoreException(ErrorCodes::INVALID_ARGUMENT, 'a userKey is required to read this store');
        }

        $salt = @hex2bin((string) ($metadata['salt'] ?? ''));
        if ($salt === false) {
            throw new KeystoreException(ErrorCodes::STORE_CORRUPT, "keystore \"{$storeName}\" has a malformed salt");
        }

        $userDerived = Crypto::stretchPassword($userKey, $salt, self::iterationsOf($metadata));
        $master = $metadata['master'] ?? null;

        if (!is_array($master)) {
            throw new KeystoreException(ErrorCodes::STORE_CORRUPT, "keystore \"{$storeName}\" has no master key");
        }

        try {
            return Crypto::decrypt(
                $master,
                $userDerived,
                self::isLegacy($metadata) ? '' : Format::CONTEXT_MASTER,
                'master key'
            );
        } catch (KeystoreException $error) {
            if ($error->getErrorCode() === ErrorCodes::BAD_USER_KEY) {
                throw new KeystoreException(
                    ErrorCodes::BAD_USER_KEY,
                    "wrong user key for keystore \"{$storeName}\"",
                    $error
                );
            }
            throw $error;
        }
    }

    /**
     * The key one value is encrypted under.
     *
     * In 3.0 that is HKDF from the master key, with the value's salt and a
     * context naming the key - so a value file moved to another key's name
     * derives a different key entirely. In 2.0 it was PBKDF2 over the master
     * key, at the store's full iteration count, with nothing binding it to the
     * name.
     *
     * @param array<string, mixed> $metadata
     * @param array<string, mixed> $record
     */
    private static function valueKey(
        string $masterKey,
        string $salt,
        string $keyName,
        array $metadata,
        array $record
    ): string {
        if (self::isLegacy($metadata)) {
            $count = $record['iterations'] ?? null;

            return Crypto::stretchPassword(
                $masterKey,
                $salt,
                is_int($count) ? $count : self::iterationsOf($metadata)
            );
        }

        return Crypto::deriveFromKey($masterKey, $salt, Format::valueContext($keyName));
    }

    /**
     * @param array{key: string, file: string} $entry
     * @param array<string, mixed> $metadata
     */
    private function readValue(string $storeName, array $entry, string $masterKey, array $metadata): string
    {
        $path = $this->storeDir($storeName) . DIRECTORY_SEPARATOR . $entry['file'];
        if (!is_file($path)) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "key \"{$entry['key']}\" is listed in " . Format::MASTER_FILE
                    . " but its file {$entry['file']} is missing"
            );
        }

        $record = json_decode((string) file_get_contents($path), true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($record)) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "the file for key \"{$entry['key']}\" is not readable JSON"
            );
        }

        $salt = @hex2bin((string) ($record['salt'] ?? ''));
        if ($salt === false) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "the file for key \"{$entry['key']}\" has a malformed salt"
            );
        }

        $key = self::valueKey($masterKey, $salt, $entry['key'], $metadata, $record);
        $data = $record['data'] ?? null;

        if (!is_array($data)) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "the file for key \"{$entry['key']}\" has no data"
            );
        }

        return Crypto::decrypt(
            $data,
            $key,
            self::valueAad($metadata, $entry['key']),
            "value for \"{$entry['key']}\""
        );
    }

    /** @param array<string, mixed> $metadata */
    private function writeValue(
        string $storeName,
        string $fileName,
        string $keyName,
        string $value,
        string $masterKey,
        array $metadata
    ): void {
        $salt = Crypto::randomBytes(Format::VALUE_SALT_LENGTH);

        $record = ['salt' => bin2hex($salt)];
        // The iteration count only means anything to a 2.0 value, where the
        // value key is stretched from the master key. A 3.0 value derives with
        // HKDF, which takes no count, so writing one would record a number
        // nothing reads.
        if (self::isLegacy($metadata)) {
            $record['iterations'] = self::iterationsOf($metadata);
        }

        $key = self::valueKey($masterKey, $salt, $keyName, $metadata, $record);
        $record['data'] = Crypto::encrypt(
            $value,
            $key,
            self::ivLengthOf($metadata),
            self::valueAad($metadata, $keyName)
        );

        file_put_contents(
            $this->storeDir($storeName) . DIRECTORY_SEPARATOR . $fileName,
            (string) json_encode($record, self::JSON_WRITE)
        );
    }

    /**
     * Encrypt a key-value file into a store, in format 3.0.
     *
     * The input format follows the extension: .json an object, .env dotenv
     * lines, anything else key:value lines with master: first. An empty store
     * name defaults to the input file's base name.
     *
     * Re-securing an existing store replaces it. The old .enc files go first, so
     * a key dropped from the input does not linger on disk as an encrypted
     * orphan that nothing references any more.
     *
     * @return array{storeName: string, storeDir: string, totalKeys: int, keys: list<string>}
     */
    public function secure(string $inputFile, string $userKey, ?string $storeName = null): array
    {
        if ($userKey === '') {
            throw new KeystoreException(ErrorCodes::INVALID_ARGUMENT, 'secure requires a userKey');
        }

        $parsed = InputFile::parse($inputFile);
        if ($parsed['masterKey'] === null || $parsed['masterKey'] === '') {
            throw new KeystoreException(
                ErrorCodes::BAD_INPUT,
                'input must define a master key (e.g. "master:..." in .txt, "master=..." in .env, '
                    . 'or a "master" property in .json)'
            );
        }

        if ($parsed['entries'] === []) {
            throw new KeystoreException(ErrorCodes::BAD_INPUT, 'no key-value entries found in input file');
        }

        $storeName = ($storeName === null || $storeName === '')
            ? pathinfo($inputFile, PATHINFO_FILENAME)
            : $storeName;

        $dir = $this->storeDir($storeName);
        if (!is_dir($dir)) {
            @mkdir($dir, 0o700, true);
        }

        foreach (scandir($dir) ?: [] as $name) {
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (!is_file($path)) {
                continue;
            }
            if (str_ends_with($name, Format::VALUE_EXTENSION) || $name === Format::MASTER_FILE) {
                @unlink($path);
            }
        }

        $storeSalt = Crypto::randomBytes(Format::STORE_SALT_LENGTH);
        $userDerived = Crypto::stretchPassword($userKey, $storeSalt, $this->iterations);

        $metadata = [
            'version' => Format::STORE_VERSION,
            'created' => self::now(),
            'salt' => bin2hex($storeSalt),
            'iterations' => $this->iterations,
            'master' => Crypto::encrypt(
                $parsed['masterKey'],
                $userDerived,
                Format::IV_LENGTH,
                Format::CONTEXT_MASTER
            ),
            'entries' => [],
            'sourceFile' => basename($inputFile),
            'totalKeys' => count($parsed['entries']),
        ];

        $keys = [];
        foreach ($parsed['entries'] as $entry) {
            $fileName = Crypto::safeFileName($entry['key']);
            $this->writeValue($storeName, $fileName, $entry['key'], $entry['value'], $parsed['masterKey'], $metadata);
            $metadata['entries'][] = ['key' => $entry['key'], 'file' => $fileName];
            $keys[] = $entry['key'];
        }

        $this->writeMetadata($storeName, $metadata);
        $this->updateIndex($storeName, $metadata);
        $this->log('Secured ' . count($keys) . " keys in keystore \"{$storeName}\" at {$dir}");

        return [
            'storeName' => $storeName,
            'storeDir' => $dir,
            'totalKeys' => count($keys),
            'keys' => $keys,
        ];
    }

    /**
     * Decrypt and return one value.
     *
     * An empty store name searches every store. That is a convenience for a
     * single-store setup and a trap for a multi-store one, where two stores may
     * hold the same key name and the first match wins - name the store when it
     * matters.
     */
    public function get(string $key, string $userKey, ?string $storeName = null): string
    {
        $storeName = ($storeName === null || $storeName === '')
            ? $this->findStoreForKey($key)
            : $storeName;

        $metadata = $this->readMetadata($storeName);

        foreach ($metadata['entries'] ?? [] as $entry) {
            if (($entry['key'] ?? null) === $key) {
                return $this->readValue(
                    $storeName,
                    $entry,
                    $this->unlockMaster($metadata, $userKey, $storeName),
                    $metadata
                );
            }
        }

        throw new KeystoreException(
            ErrorCodes::KEY_NOT_FOUND,
            "key \"{$key}\" not found in keystore \"{$storeName}\""
        );
    }

    /**
     * Decrypt every value in a store.
     *
     * The user key is stretched once, not once per value, so this costs one
     * PBKDF2 derivation however many keys the store holds.
     *
     * @return array<string, string>
     */
    public function getAll(string $userKey, string $storeName): array
    {
        $metadata = $this->readMetadata($storeName);
        $masterKey = $this->unlockMaster($metadata, $userKey, $storeName);

        $values = [];
        foreach ($metadata['entries'] ?? [] as $entry) {
            $values[$entry['key']] = $this->readValue($storeName, $entry, $masterKey, $metadata);
        }

        return $values;
    }

    /**
     * Add a key, or replace the value of one already there.
     *
     * The replacement gets a fresh salt and a fresh IV, so an observer who kept
     * the old file learns nothing by comparing it with the new one.
     *
     * On a store still in format 2.0 this writes a 2.0 record, so the store
     * stays internally consistent. Run migrate() to move the whole store to 3.0.
     *
     * @return array{key: string, storeName: string, added: bool, format: string}
     */
    public function set(string $key, string $value, string $userKey, string $storeName): array
    {
        if ($key === '') {
            throw new KeystoreException(ErrorCodes::INVALID_ARGUMENT, 'set requires a key');
        }

        $metadata = $this->readMetadata($storeName);
        $masterKey = $this->unlockMaster($metadata, $userKey, $storeName);

        $fileName = null;
        foreach ($metadata['entries'] ?? [] as $entry) {
            if (($entry['key'] ?? null) === $key) {
                $fileName = $entry['file'];
                break;
            }
        }

        $added = $fileName === null;
        $fileName ??= Crypto::safeFileName($key);

        $this->writeValue($storeName, $fileName, $key, $value, $masterKey, $metadata);

        if ($added) {
            $metadata['entries'][] = ['key' => $key, 'file' => $fileName];
            $metadata['totalKeys'] = count($metadata['entries']);
        }

        $this->writeMetadata($storeName, $metadata);
        $this->updateIndex($storeName, $metadata);
        $this->log("Key \"{$key}\" " . ($added ? 'added' : 'updated') . " in keystore \"{$storeName}\"");

        return [
            'key' => $key,
            'storeName' => $storeName,
            'added' => $added,
            'format' => self::formatOf($metadata),
        ];
    }

    /**
     * Rewrite a whole store in the current format.
     *
     * Every value is decrypted with the old parameters and re-encrypted with the
     * new ones, under a fresh store salt and fresh per-value salts. The master
     * key itself does not change, so nothing outside the store has to be told.
     *
     * A store already on the current format is re-encrypted rather than skipped,
     * which is what makes this the way to raise a store's iteration count as
     * well as its format.
     *
     * The rewrite is not atomic. Every value is decrypted before anything is
     * written, so a wrong user key changes nothing; and every new value file is
     * written before master.json, so an interruption leaves the store readable
     * in its old format. Export first anyway.
     *
     * @return array{storeName: string, from: string, to: string, keys: list<string>, iterations: int}
     */
    public function migrate(string $storeName, string $userKey): array
    {
        $metadata = $this->readMetadata($storeName);
        $from = self::formatOf($metadata);
        $masterKey = $this->unlockMaster($metadata, $userKey, $storeName);

        // Decrypt everything up front. If any value fails, the store is untouched.
        $values = [];
        foreach ($metadata['entries'] ?? [] as $entry) {
            $values[] = [$entry['key'], $this->readValue($storeName, $entry, $masterKey, $metadata)];
        }

        $storeSalt = Crypto::randomBytes(Format::STORE_SALT_LENGTH);
        $userDerived = Crypto::stretchPassword($userKey, $storeSalt, $this->iterations);

        $rewritten = $metadata;
        $rewritten['version'] = Format::STORE_VERSION;
        $rewritten['salt'] = bin2hex($storeSalt);
        $rewritten['iterations'] = $this->iterations;
        $rewritten['master'] = Crypto::encrypt(
            $masterKey,
            $userDerived,
            Format::IV_LENGTH,
            Format::CONTEXT_MASTER
        );
        $rewritten['migrated'] = self::now();
        $rewritten['entries'] = [];
        $rewritten['totalKeys'] = count($values);

        $dir = $this->storeDir($storeName);
        $stale = [];
        foreach (scandir($dir) ?: [] as $name) {
            if (str_ends_with($name, Format::VALUE_EXTENSION)) {
                $stale[$name] = true;
            }
        }

        $keys = [];
        foreach ($values as [$keyName, $value]) {
            $fileName = Crypto::safeFileName($keyName);
            $this->writeValue($storeName, $fileName, $keyName, $value, $masterKey, $rewritten);
            $rewritten['entries'][] = ['key' => $keyName, 'file' => $fileName];
            $keys[] = $keyName;
            unset($stale[$fileName]);
        }

        $this->writeMetadata($storeName, $rewritten);
        foreach (array_keys($stale) as $name) {
            @unlink($dir . DIRECTORY_SEPARATOR . $name);
        }

        $this->updateIndex($storeName, $rewritten);
        $this->log(
            $from === Format::STORE_VERSION
                ? "Keystore \"{$storeName}\" re-encrypted in format " . Format::STORE_VERSION
                    . " at {$this->iterations} iterations"
                : "Keystore \"{$storeName}\" migrated from format {$from} to " . Format::STORE_VERSION
        );

        return [
            'storeName' => $storeName,
            'from' => $from,
            'to' => Format::STORE_VERSION,
            'keys' => $keys,
            'iterations' => $this->iterations,
        ];
    }

    /** Remove one key and its encrypted file. */
    public function deleteKey(string $key, string $storeName): void
    {
        $metadata = $this->readMetadata($storeName);

        $removed = null;
        $kept = [];
        foreach ($metadata['entries'] ?? [] as $entry) {
            if (($entry['key'] ?? null) === $key) {
                $removed = $entry;
                continue;
            }
            $kept[] = $entry;
        }

        if ($removed === null) {
            throw new KeystoreException(
                ErrorCodes::KEY_NOT_FOUND,
                "key \"{$key}\" not found in keystore \"{$storeName}\""
            );
        }

        $metadata['entries'] = $kept;
        $metadata['totalKeys'] = count($kept);

        @unlink($this->storeDir($storeName) . DIRECTORY_SEPARATOR . $removed['file']);

        $this->writeMetadata($storeName, $metadata);
        $this->updateIndex($storeName, $metadata);
        $this->log("Key \"{$key}\" deleted from keystore \"{$storeName}\"");
    }

    /**
     * The names of every store under this keystore directory.
     *
     * A directory counts as a store only if it holds a master.json, so an
     * unrelated directory sitting alongside is not reported as one.
     *
     * @return list<string>
     */
    public function listStores(): array
    {
        if (!is_dir($this->keystoreDir)) {
            return [];
        }

        $stores = [];
        foreach (scandir($this->keystoreDir) ?: [] as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $master = $this->keystoreDir . DIRECTORY_SEPARATOR . $name . DIRECTORY_SEPARATOR . Format::MASTER_FILE;
            if (is_file($master)) {
                $stores[] = $name;
            }
        }

        return $stores;
    }

    /**
     * The key names in a store.
     *
     * No user key, and none is needed: names live in metadata in the clear. That
     * is a deliberate trade - it is what makes listing useful without a password
     * - and it means a key name must not itself be a secret.
     *
     * @return list<string>
     */
    public function listKeys(string $storeName): array
    {
        $keys = [];
        foreach ($this->readMetadata($storeName)['entries'] ?? [] as $entry) {
            $keys[] = $entry['key'];
        }

        return $keys;
    }

    /**
     * Everything about a store that can be known without decrypting anything.
     *
     * @return array<string, mixed>
     */
    public function getStoreInfo(string $storeName): array
    {
        $metadata = $this->readMetadata($storeName);
        $created = $metadata['created'] ?? '';

        return [
            'name' => $storeName,
            'path' => $this->storeDir($storeName),
            'version' => self::formatOf($metadata),
            'current' => !self::isLegacy($metadata),
            'created' => $created,
            'updated' => $metadata['updated'] ?? $created,
            'iterations' => self::iterationsOf($metadata),
            'totalKeys' => $metadata['totalKeys'] ?? count($metadata['entries'] ?? []),
            'keys' => $this->listKeys($storeName),
            'sourceFile' => $metadata['sourceFile'] ?? '',
        ];
    }

    /**
     * Write a store to a single portable bundle, .skb by default.
     *
     * The contents are already encrypted, so the bundle is safe to move through
     * a CI artifact store or an scp.
     */
    public function exportStore(string $storeName, ?string $backupPath = null): string
    {
        $this->readMetadata($storeName); // refuse early if it is not a store

        if ($backupPath === null || $backupPath === '') {
            $stamp = (int) (microtime(true) * 1000);
            $backupPath = getcwd() . DIRECTORY_SEPARATOR
                . "{$storeName}-backup-{$stamp}" . Format::DEFAULT_BACKUP_EXTENSION;
        }

        $bundle = Bundle::build($this->storeDir($storeName), $storeName);
        file_put_contents($backupPath, (string) json_encode($bundle, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        $this->log("Store \"{$storeName}\" exported to {$backupPath}");

        return $backupPath;
    }

    /** Restore a bundle, under its own name or a new one. */
    public function importStore(string $backupPath, ?string $storeName = null): string
    {
        $bundle = Bundle::read($backupPath);

        $target = ($storeName === null || $storeName === '') ? ($bundle['storeName'] ?? '') : $storeName;
        if ($target === '') {
            throw new KeystoreException(
                ErrorCodes::BAD_BACKUP,
                'cannot determine a target store name: the bundle names none and none was given'
            );
        }

        Bundle::write($bundle, $this->storeDir($target));
        $this->updateIndex($target, $this->readMetadata($target));
        $this->log("Store imported as \"{$target}\"");

        return $target;
    }

    /** Remove a store and its index entry. There is no undo; export first. */
    public function deleteStore(string $storeName): void
    {
        $this->readMetadata($storeName); // refuse to delete a directory that is not a store

        $dir = $this->storeDir($storeName);
        foreach (scandir($dir) ?: [] as $name) {
            if ($name !== '.' && $name !== '..') {
                @unlink($dir . DIRECTORY_SEPARATOR . $name);
            }
        }
        @rmdir($dir);

        $indexPath = $this->keystoreDir . DIRECTORY_SEPARATOR . Format::INDEX_FILE;
        if (is_file($indexPath)) {
            $catalogue = json_decode((string) file_get_contents($indexPath), true);
            if (is_array($catalogue) && isset($catalogue['stores']) && is_array($catalogue['stores'])) {
                unset($catalogue['stores'][$storeName]);
                $catalogue['updated'] = self::now();
                file_put_contents($indexPath, (string) json_encode($catalogue, self::JSON_WRITE));
            }
        }

        $this->log("Keystore \"{$storeName}\" deleted");
    }

    /** Instance sugar for ValueToken::encrypt. */
    public function encryptValue(?string $plaintext, string $userKey, ?int $iterations = null): ?string
    {
        return ValueToken::encrypt($plaintext, $userKey, $iterations);
    }

    /** Instance sugar for ValueToken::decrypt. */
    public function decryptValue(mixed $token, string $userKey): mixed
    {
        return ValueToken::decrypt($token, $userKey);
    }

    /**
     * Rewrite this store's entry in the keystore-wide catalogue.
     *
     * The catalogue holds names and counts and no secrets, which is what makes
     * it safe to read without a user key - and what makes it merely a
     * convenience: every operation reads the store's own master.json for
     * anything that matters.
     *
     * @param array<string, mixed> $metadata
     */
    private function updateIndex(string $storeName, array $metadata): void
    {
        $indexPath = $this->keystoreDir . DIRECTORY_SEPARATOR . Format::INDEX_FILE;

        $catalogue = ['stores' => []];
        if (is_file($indexPath)) {
            $loaded = json_decode((string) file_get_contents($indexPath), true);
            // A corrupt catalogue is not worth failing a write over - it holds
            // nothing that is not also in each store's own metadata.
            if (is_array($loaded) && isset($loaded['stores']) && is_array($loaded['stores'])) {
                $catalogue = $loaded;
            }
        }

        $keys = [];
        foreach ($metadata['entries'] ?? [] as $entry) {
            $keys[] = $entry['key'];
        }

        $catalogue['stores'][$storeName] = [
            'version' => self::formatOf($metadata),
            'created' => $metadata['created'] ?? null,
            'totalKeys' => $metadata['totalKeys'] ?? count($keys),
            'keys' => $keys,
            'sourceFile' => $metadata['sourceFile'] ?? null,
        ];
        $catalogue['updated'] = self::now();

        file_put_contents($indexPath, (string) json_encode($catalogue, self::JSON_WRITE));
    }

    /** The first store holding this key. */
    private function findStoreForKey(string $key): string
    {
        foreach ($this->listStores() as $storeName) {
            try {
                if (in_array($key, $this->listKeys($storeName), true)) {
                    return $storeName;
                }
            } catch (KeystoreException) {
                continue; // a store we cannot read is not a store that holds the key
            }
        }

        throw new KeystoreException(ErrorCodes::KEY_NOT_FOUND, "key \"{$key}\" not found in any keystore");
    }
}
