'use strict';

// One error type, with a code.
//
// Before this the library threw bare `Error`s with prose messages, and a caller
// who wanted to tell "wrong password" from "no such store" had no option but to
// match on the text. Worse, a wrong user key surfaced as node's own
// `Unsupported state or unable to authenticate data`, which says nothing to
// anyone who has not read the GCM source.
//
// A code is a promise: the message may be reworded, the code will not be.

/**
 * KeystoreError is thrown by every operation in this library that can fail in a
 * way the caller might want to handle rather than merely report.
 *
 * @property {string} code    a stable identifier from {@link ErrorCodes}
 * @property {Error} [cause]  the underlying error, when there was one
 */
class KeystoreError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'KeystoreError';
    this.code = code;
    if (options.cause !== undefined) this.cause = options.cause;
    if (Error.captureStackTrace) Error.captureStackTrace(this, KeystoreError);
  }
}

/**
 * Every code KeystoreError can carry. Exported as an object rather than kept as
 * loose strings so a typo in a caller's `catch` is a reference error rather than
 * a branch that silently never runs.
 */
const ErrorCodes = {
  /** The options given to the constructor do not make sense. */
  INVALID_OPTIONS: 'INVALID_OPTIONS',
  /** A required argument was missing or empty. */
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  /** The named store does not exist under this keystore directory. */
  STORE_NOT_FOUND: 'STORE_NOT_FOUND',
  /** The store directory exists but its master.json does not. */
  STORE_CORRUPT: 'STORE_CORRUPT',
  /** The named key is not in this store - or in any store, when none was named. */
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  /** Decryption failed: the user key is wrong, or the bytes have been tampered with. */
  BAD_USER_KEY: 'BAD_USER_KEY',
  /** A stateless value token is not in the form this library writes. */
  BAD_TOKEN: 'BAD_TOKEN',
  /** The input file could not be read as the format its extension claims. */
  BAD_INPUT: 'BAD_INPUT',
  /** The backup bundle is missing, unreadable, or not a keystore bundle. */
  BAD_BACKUP: 'BAD_BACKUP',
  /** The store or bundle is in a format version newer than this build reads. */
  UNSUPPORTED_FORMAT: 'UNSUPPORTED_FORMAT'
};

/** Convenience: build and throw in one expression. */
function fail(code, message, options) {
  throw new KeystoreError(code, message, options);
}

module.exports = { KeystoreError, ErrorCodes, fail };
