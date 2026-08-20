<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * Encryption with no store behind it.
 *
 * Keystore owns a directory. These methods own nothing: they take a secret and a
 * user key and give back a string, which the caller puts wherever it already
 * keeps things - a database column, a config row, a queue message. There is no
 * master key and no file, so there is also no keystore to deploy alongside the
 * application.
 *
 * The token is self-describing, and says so in its first field:
 *
 *   skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>     written and read
 *   skv1:<salt>:<iv>:<authTag>:<ciphertext>                  read only
 *
 * What skv1 lacked was a field for its iteration count, which is why its count
 * is frozen at 100,000 forever and skv2's is not.
 */
final class ValueToken
{
    /** True if the value is a token this format defines, of either version. */
    public static function isEncryptedValue(mixed $value): bool
    {
        return is_string($value)
            && (str_starts_with($value, Format::TOKEN_PREFIX . ':')
                || str_starts_with($value, Format::TOKEN_PREFIX_LEGACY . ':'));
    }

    /** "skv2", "skv1", or null if the value is not a token. */
    public static function tokenVersion(mixed $value): ?string
    {
        if (!self::isEncryptedValue($value)) {
            return null;
        }

        /** @var string $value */
        return substr($value, 0, (int) strpos($value, ':'));
    }

    /**
     * Encrypt one string under a user key, with nothing on disk.
     *
     * A fresh random salt stretches the key and a fresh random IV feeds
     * AES-256-GCM, so encrypting the same secret twice gives two different
     * tokens - which is what stops a database column from revealing which rows
     * share a value.
     *
     * Null and the empty string are returned unchanged, matching every other
     * implementation, so this can be mapped over a record without first sorting
     * the empty fields out of it.
     *
     * Unlike a store, there is no master key here: every token is stretched
     * straight from the user key, so the default cost is paid on every single
     * value. Encrypting a whole column is the case where that matters, and
     * $iterations is there for it - the count is recorded in the token, so
     * decryption follows whatever was chosen.
     */
    public static function encrypt(?string $plaintext, string $userKey, ?int $iterations = null): ?string
    {
        if ($plaintext === null || $plaintext === '') {
            return $plaintext;
        }

        if ($userKey === '') {
            throw new KeystoreException(ErrorCodes::INVALID_ARGUMENT, 'encryptValue requires a userKey');
        }

        $count = $iterations ?? Format::DEFAULT_ITERATIONS;
        if ($count < Format::MIN_ITERATIONS) {
            throw new KeystoreException(
                ErrorCodes::INVALID_ARGUMENT,
                'iterations must be at least ' . Format::MIN_ITERATIONS . ", not {$count}"
            );
        }

        $salt = Crypto::randomBytes(Format::TOKEN_SALT_LENGTH);
        $key = Crypto::stretchPassword($userKey, $salt, $count);
        $record = Crypto::encrypt($plaintext, $key, Format::IV_LENGTH, Format::CONTEXT_TOKEN);

        return implode(':', [
            Format::TOKEN_PREFIX,
            (string) $count,
            bin2hex($salt),
            $record['iv'],
            $record['authTag'],
            $record['data'],
        ]);
    }

    /**
     * Reverse encrypt(), for either token version.
     *
     * Anything that is not a token is returned unchanged, so a column part way
     * through being encrypted can be read with one call rather than a
     * conditional at every site. A token that is malformed, altered, or written
     * under a different user key throws - that case is never silently passed
     * through, because doing so would hand the caller ciphertext it believed was
     * plaintext.
     */
    public static function decrypt(mixed $token, string $userKey): mixed
    {
        if (!self::isEncryptedValue($token)) {
            return $token;
        }

        if ($userKey === '') {
            throw new KeystoreException(ErrorCodes::INVALID_ARGUMENT, 'decryptValue requires a userKey');
        }

        /** @var string $token */
        $parts = explode(':', $token);
        $legacy = $parts[0] === Format::TOKEN_PREFIX_LEGACY;
        $expected = $legacy ? Format::TOKEN_PARTS_LEGACY : Format::TOKEN_PARTS;

        if (count($parts) !== $expected) {
            throw new KeystoreException(
                ErrorCodes::BAD_TOKEN,
                "not a {$parts[0]} token: expected {$expected} colon-separated fields, found " . count($parts)
            );
        }

        if ($legacy) {
            // skv1 has no iteration field, and every one ever written used
            // 100,000. It also predates additional authenticated data and the
            // 12-byte IV; both are read as they were written.
            $iterations = Format::TOKEN_ITERATIONS_LEGACY;
            [$saltHex, $iv, $authTag, $data] = [$parts[1], $parts[2], $parts[3], $parts[4]];
            $aad = '';
        } else {
            if (!ctype_digit($parts[1]) || (int) $parts[1] < 1) {
                throw new KeystoreException(
                    ErrorCodes::BAD_TOKEN,
                    "token iteration count is not a positive whole number: \"{$parts[1]}\""
                );
            }
            $iterations = (int) $parts[1];
            [$saltHex, $iv, $authTag, $data] = [$parts[2], $parts[3], $parts[4], $parts[5]];
            $aad = Format::CONTEXT_TOKEN;
        }

        $salt = @hex2bin($saltHex);
        if ($salt === false) {
            throw new KeystoreException(ErrorCodes::BAD_TOKEN, 'token salt is not hex');
        }

        $key = Crypto::stretchPassword($userKey, $salt, $iterations);

        return Crypto::decrypt(
            ['iv' => $iv, 'authTag' => $authTag, 'data' => $data],
            $key,
            $aad,
            'value'
        );
    }

    private function __construct()
    {
    }
}
