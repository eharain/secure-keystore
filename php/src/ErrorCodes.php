<?php

declare(strict_types=1);

namespace TechStyle\SecureKeystore;

/**
 * Every code a KeystoreException can carry.
 *
 * These strings are identical in every implementation of the format:
 * BAD_USER_KEY means the same thing in PHP, Go, .NET, Python, Rust and
 * JavaScript, and a script that greps for it keeps working when the team
 * rewrites the service. The message may be reworded between releases; the code
 * will not be.
 */
final class ErrorCodes
{
    /** The options given do not make sense. */
    public const INVALID_OPTIONS = 'INVALID_OPTIONS';

    /** A required argument was missing or empty. */
    public const INVALID_ARGUMENT = 'INVALID_ARGUMENT';

    /** No such store under this keystore directory. */
    public const STORE_NOT_FOUND = 'STORE_NOT_FOUND';

    /** The directory exists but is not a store, or its metadata is unreadable. */
    public const STORE_CORRUPT = 'STORE_CORRUPT';

    /** No such key - in the named store, or in any of them. */
    public const KEY_NOT_FOUND = 'KEY_NOT_FOUND';

    /** Decryption failed: the key is wrong, or the bytes have been altered. */
    public const BAD_USER_KEY = 'BAD_USER_KEY';

    /** A value token is not in the form this format defines. */
    public const BAD_TOKEN = 'BAD_TOKEN';

    /** The input file is not readable as the format its extension claims. */
    public const BAD_INPUT = 'BAD_INPUT';

    /** The bundle is missing, unreadable, or not a keystore bundle. */
    public const BAD_BACKUP = 'BAD_BACKUP';

    /** The store or bundle is in a format version newer than this build reads. */
    public const UNSUPPORTED_FORMAT = 'UNSUPPORTED_FORMAT';

    private function __construct()
    {
    }
}
