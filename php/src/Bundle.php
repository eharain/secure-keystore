<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * Export and import, as one JSON bundle.
 *
 * The contents are already encrypted, so a bundle is safe to put through a CI
 * artifact store or an scp, and useless to anyone who intercepts it without the
 * user key. It is pure JSON - no tar, no shell - so it behaves the same on every
 * platform.
 */
final class Bundle
{
    /**
     * Read every file in a store directory into a bundle.
     *
     * @return array{format: string, version: int, storeName: string, files: array<string, string>}
     */
    public static function build(string $storeDir, string $storeName): array
    {
        $files = [];

        foreach (scandir($storeDir) ?: [] as $name) {
            $path = $storeDir . DIRECTORY_SEPARATOR . $name;
            if ($name === '.' || $name === '..' || !is_file($path)) {
                continue;
            }
            $files[$name] = (string) file_get_contents($path);
        }

        return [
            'format' => Format::BACKUP_FORMAT,
            'version' => Format::BACKUP_VERSION,
            'storeName' => $storeName,
            'files' => $files,
        ];
    }

    /**
     * Read a bundle off disk and check it is one of ours before any of it is
     * believed.
     *
     * The checks are in the order that matters: a file that is not JSON, a JSON
     * document that is not a bundle, a bundle from a future version, and a
     * bundle with no master.json are four different mistakes and each says so.
     *
     * @return array{format: string, version: int, storeName: string, files: array<string, string>}
     */
    public static function read(string $backupPath): array
    {
        if (!is_file($backupPath)) {
            throw new KeystoreException(ErrorCodes::BAD_BACKUP, "backup file not found: {$backupPath}");
        }

        $bundle = json_decode((string) file_get_contents($backupPath), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new KeystoreException(
                ErrorCodes::BAD_BACKUP,
                "invalid backup file: {$backupPath} is not readable as JSON"
            );
        }

        if (
            !is_array($bundle)
            || ($bundle['format'] ?? null) !== Format::BACKUP_FORMAT
            || !isset($bundle['files']) || !is_array($bundle['files'])
        ) {
            throw new KeystoreException(
                ErrorCodes::BAD_BACKUP,
                "invalid backup file: {$backupPath} is not a keystore bundle"
            );
        }

        $version = $bundle['version'] ?? 0;
        if (is_int($version) && $version > Format::BACKUP_VERSION) {
            throw new KeystoreException(
                ErrorCodes::UNSUPPORTED_FORMAT,
                "backup was written in bundle format {$version}, and this build reads up to "
                    . Format::BACKUP_VERSION
            );
        }

        if (!isset($bundle['files'][Format::MASTER_FILE])) {
            throw new KeystoreException(
                ErrorCodes::BAD_BACKUP,
                'invalid backup: ' . Format::MASTER_FILE . ' not found in bundle'
            );
        }

        /** @var array{format: string, version: int, storeName: string, files: array<string, string>} $bundle */
        return $bundle;
    }

    /**
     * Write a bundle's files into a target directory.
     *
     * Every name is reduced to its base name first. A bundle is an untrusted
     * file that arrived over a wire, and
     * {"files": {"../../.ssh/authorized_keys": "..."}} is a bundle someone could
     * write by hand.
     *
     * basename() alone follows the host's separator, so both are handled
     * explicitly - a bundle written on Windows must be as safe on Linux.
     *
     * @param array{files: array<string, string>} $bundle
     */
    public static function write(array $bundle, string $targetDir): void
    {
        if (!is_dir($targetDir) && !@mkdir($targetDir, 0o700, true) && !is_dir($targetDir)) {
            throw new KeystoreException(ErrorCodes::BAD_BACKUP, "could not create {$targetDir}");
        }

        foreach ($bundle['files'] as $name => $content) {
            $safe = self::baseName((string) $name);
            if ($safe === '' || $safe === '.' || $safe === '..') {
                continue;
            }
            file_put_contents($targetDir . DIRECTORY_SEPARATOR . $safe, $content);
        }
    }

    /** Strip every directory component, whichever separator was used. */
    private static function baseName(string $name): string
    {
        for ($index = strlen($name) - 1; $index >= 0; $index--) {
            if ($name[$index] === '/' || $name[$index] === '\\') {
                return substr($name, $index + 1);
            }
        }

        // A drive-relative name like "C:evil.txt" has no separator at all.
        if (strlen($name) > 1 && $name[1] === ':') {
            return substr($name, 2);
        }

        return $name;
    }

    private function __construct()
    {
    }
}
