<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * Reading an input file into a master key and a list of entries.
 *
 * Three formats, chosen by extension, all saying the same thing. They are parsed
 * here rather than in the store so that each can be tested against a string,
 * with no directory involved.
 */
final class InputFile
{
    /** master:<key> on the first line, then key:value lines. */
    public const FORMAT_COLON = 'colon';

    /** dotenv: KEY=value, with comments, quotes and `export`. */
    public const FORMAT_ENV = 'env';

    /** A flat object with a "master" property. */
    public const FORMAT_JSON = 'json';

    /**
     * The format an input file will be read as, from its extension.
     * ".json" and ".env" are named; everything else is the colon format.
     */
    public static function formatFor(string $inputFile): string
    {
        $extension = strtolower(pathinfo($inputFile, PATHINFO_EXTENSION));

        return match ($extension) {
            'json' => self::FORMAT_JSON,
            'env' => self::FORMAT_ENV,
            default => self::FORMAT_COLON,
        };
    }

    /**
     * Read a file and parse it as whatever its extension says it is.
     *
     * @return array{masterKey: ?string, entries: list<array{key: string, value: string}>}
     */
    public static function parse(string $inputFile): array
    {
        $content = @file_get_contents($inputFile);
        if ($content === false) {
            throw new KeystoreException(ErrorCodes::BAD_INPUT, "could not read input file: {$inputFile}");
        }

        return self::parseText($content, self::formatFor($inputFile));
    }

    /**
     * Parse input text in a named format. The file-free half of parse().
     *
     * @return array{masterKey: ?string, entries: list<array{key: string, value: string}>}
     */
    public static function parseText(string $content, string $format): array
    {
        return match ($format) {
            self::FORMAT_JSON => self::parseJson($content),
            self::FORMAT_ENV => self::parseEnv($content),
            self::FORMAT_COLON => self::parseColon($content),
            default => throw new KeystoreException(ErrorCodes::BAD_INPUT, "unknown input format: {$format}"),
        };
    }

    /**
     * The default format: master:<key> first, then key:value.
     *
     * Only the first colon splits, so a value may contain as many more as it
     * likes - which is what lets a URL or a connection string go in without
     * escaping.
     *
     * @return array{masterKey: ?string, entries: list<array{key: string, value: string}>}
     */
    private static function parseColon(string $content): array
    {
        $lines = array_values(array_filter(
            array_map('trim', explode("\n", $content)),
            static fn (string $line): bool => $line !== ''
        ));

        if ($lines === []) {
            throw new KeystoreException(ErrorCodes::BAD_INPUT, 'input file is empty');
        }

        $first = explode(':', $lines[0], 2);
        if (count($first) !== 2 || $first[0] !== Format::MASTER_ENTRY_KEY) {
            throw new KeystoreException(
                ErrorCodes::BAD_INPUT,
                'first line must be "' . Format::MASTER_ENTRY_KEY . ':your_master_key"'
            );
        }

        $entries = [];
        foreach (array_slice($lines, 1) as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $entries[] = ['key' => $parts[0], 'value' => $parts[1]];
        }

        return ['masterKey' => $first[1], 'entries' => $entries];
    }

    /**
     * dotenv syntax.
     *
     * Lines beginning "#" are skipped, as are lines with no "=" and lines with
     * an empty key. A leading "export " is stripped. A matched pair of single or
     * double quotes around the whole value is stripped - no escape sequences are
     * interpreted. The master entry may appear anywhere.
     *
     * @return array{masterKey: ?string, entries: list<array{key: string, value: string}>}
     */
    private static function parseEnv(string $content): array
    {
        $masterKey = null;
        $entries = [];

        foreach (explode("\n", $content) as $raw) {
            $line = trim($raw);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (str_starts_with($line, 'export ')) {
                $line = trim(substr($line, strlen('export ')));
            }

            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }

            $key = trim($parts[0]);
            if ($key === '') {
                continue;
            }

            $value = trim($parts[1]);
            if (strlen($value) >= 2) {
                $first = $value[0];
                $last = $value[strlen($value) - 1];
                if ($first === $last && ($first === '"' || $first === "'")) {
                    $value = substr($value, 1, -1);
                }
            }

            if ($key === Format::MASTER_ENTRY_KEY) {
                $masterKey = $value;
                continue;
            }

            $entries[] = ['key' => $key, 'value' => $value];
        }

        return ['masterKey' => $masterKey, 'entries' => $entries];
    }

    /**
     * A flat object.
     *
     * Values that are not strings are serialised to their JSON form rather than
     * refused, so a port number or a feature flag lifted straight out of an
     * existing config file goes in without being quoted first. Everything comes
     * back out as a string, which is what the store holds.
     *
     * @return array{masterKey: ?string, entries: list<array{key: string, value: string}>}
     */
    private static function parseJson(string $content): array
    {
        $document = json_decode($content, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new KeystoreException(ErrorCodes::BAD_INPUT, 'invalid JSON input file');
        }

        if (!is_array($document) || array_is_list($document)) {
            throw new KeystoreException(ErrorCodes::BAD_INPUT, 'JSON input must be an object of key-value pairs');
        }

        $masterKey = null;
        $entries = [];

        foreach ($document as $key => $value) {
            $text = is_string($value)
                ? $value
                : json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

            if ((string) $key === Format::MASTER_ENTRY_KEY) {
                $masterKey = $text;
                continue;
            }

            $entries[] = ['key' => (string) $key, 'value' => (string) $text];
        }

        return ['masterKey' => $masterKey, 'entries' => $entries];
    }

    private function __construct()
    {
    }
}
