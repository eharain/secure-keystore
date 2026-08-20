<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * The cryptographic primitives, and nothing else.
 *
 * Every AES call in this package goes through this class, so there is exactly
 * one place where an algorithm, an IV length or an encoding is chosen.
 *
 * Two derivations, for two different jobs, which format 2.0 conflated.
 * stretchPassword turns a password into a key and is deliberately slow;
 * deriveFromKey turns a key into another key and is fast, because the input is
 * already high-entropy and stretching it buys nothing. Running 600,000 PBKDF2
 * rounds on the master key once per value - which 2.0 did - costs seconds on a
 * store of any size and adds no security the master key did not already have.
 */
final class Crypto
{
    /**
     * PBKDF2-HMAC-SHA256: a password, stretched.
     *
     * The final `true` is what makes hash_pbkdf2 return raw bytes; without it
     * the result is hex, at twice the length, and every derived key would be
     * wrong in a way that still "works" within one implementation and nowhere
     * else.
     *
     * The count is a parameter rather than a constant because it is recorded
     * alongside whatever it derives. Deriving with a count that does not match
     * the one a record was written with produces a different key, and the GCM
     * tag then rejects it - which is the failure you want rather than the one
     * where it nearly works.
     */
    public static function stretchPassword(string $password, string $salt, int $iterations): string
    {
        return hash_pbkdf2('sha256', $password, $salt, $iterations, Format::KEY_LENGTH, true);
    }

    /**
     * HKDF-SHA256: one key into another, bound to a context.
     *
     * The input is the master key, which is already a strong secret, so there is
     * nothing to stretch - the job is separation, not hardening. The info
     * carries the context that separates them, and for a value that context
     * contains the key name, which is half of what stops two value files being
     * swapped. The other half is the same string passed as GCM additional data.
     */
    public static function deriveFromKey(string $key, string $salt, string $info): string
    {
        return hash_hkdf('sha256', $key, Format::KEY_LENGTH, $info, $salt);
    }

    /** Random bytes from the system source. */
    public static function randomBytes(int $length): string
    {
        return random_bytes($length);
    }

    /**
     * Seal a plaintext under a fresh random IV, so the same plaintext under the
     * same key never produces the same bytes twice.
     *
     * `$aad` is empty for a format 2.0 record, which bound nothing.
     *
     * @return array{iv: string, authTag: string, data: string} all lowercase hex
     */
    public static function encrypt(
        string $plaintext,
        string $key,
        int $ivLength = Format::IV_LENGTH,
        string $aad = ''
    ): array {
        $iv = self::randomBytes($ivLength);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            Format::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            Format::AUTH_TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new KeystoreException(
                ErrorCodes::INVALID_ARGUMENT,
                'encryption failed: ' . (openssl_error_string() ?: 'no detail from openssl')
            );
        }

        return [
            'iv' => bin2hex($iv),
            'authTag' => bin2hex($tag),
            'data' => bin2hex($ciphertext),
        ];
    }

    /**
     * Reverse encrypt(), and translate the failure.
     *
     * GCM cannot tell a wrong key from tampered bytes from mismatched additional
     * data - all three are a tag that does not verify - and openssl_decrypt
     * reports any of them by returning false, which a caller could mistake for
     * an empty value. All three become BAD_USER_KEY here.
     *
     * @param array<string, mixed> $record
     */
    public static function decrypt(array $record, string $key, string $aad = '', string $what = 'value'): string
    {
        foreach (['iv', 'authTag', 'data'] as $field) {
            if (!isset($record[$field]) || !is_string($record[$field])) {
                throw new KeystoreException(
                    ErrorCodes::STORE_CORRUPT,
                    "the encrypted {$what} is missing its iv, authTag or data"
                );
            }
        }

        $iv = @hex2bin($record['iv']);
        $tag = @hex2bin($record['authTag']);
        $data = @hex2bin($record['data']);

        if ($iv === false || $tag === false || $data === false) {
            throw new KeystoreException(
                ErrorCodes::STORE_CORRUPT,
                "the encrypted {$what} has a malformed hex field"
            );
        }

        if ($iv === '') {
            throw new KeystoreException(ErrorCodes::STORE_CORRUPT, "the encrypted {$what} has an empty iv");
        }

        $plaintext = openssl_decrypt(
            $data,
            Format::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw new KeystoreException(
                ErrorCodes::BAD_USER_KEY,
                "could not decrypt the {$what}: the key is wrong, or the stored bytes have been altered"
            );
        }

        return $plaintext;
    }

    /**
     * A filesystem-safe, collision-resistant filename for a key.
     *
     * The stem is for humans, so it is the key with anything unsafe replaced -
     * which neutralises "../", drive letters and the characters Windows refuses.
     * Sanitising alone would map "a/b" and "a_b" onto one file, so the real
     * identity is the hash suffix; the stem is only a label.
     *
     * The stem is truncated by bytes, matching every other implementation. A
     * multi-byte character straddling the limit is cut, but the name is a label
     * and the hash is the identity, so a mangled label costs nothing.
     */
    public static function safeFileName(string $key): string
    {
        $stem = preg_replace('/[^A-Za-z0-9._-]/', '_', substr($key, 0, Format::FILENAME_STEM_LIMIT));
        $hash = substr(hash('sha256', $key), 0, Format::FILENAME_HASH_LENGTH);

        return $stem . '-' . $hash . Format::VALUE_EXTENSION;
    }

    private function __construct()
    {
    }
}
