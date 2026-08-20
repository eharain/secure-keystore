'use strict';

const {
  VALUE_TOKEN_PREFIX,
  VALUE_TOKEN_PARTS,
  VALUE_TOKEN_PREFIX_LEGACY,
  VALUE_TOKEN_PARTS_LEGACY,
  TOKEN_SALT_LENGTH,
  TOKEN_KDF_ITERATIONS_LEGACY,
  DEFAULT_KDF_ITERATIONS,
  MIN_KDF_ITERATIONS,
  IV_LENGTH,
  IV_LENGTH_LEGACY,
  CONTEXT_TOKEN,
  ENCODING
} = require('./constants');
const { randomSalt, stretchPassword, encrypt, decrypt } = require('./crypto');
const { KeystoreError, ErrorCodes } = require('./errors');

// Encryption with no store behind it.
//
// The rest of this library owns a directory. These two functions own nothing:
// they take a secret and a user key and give back a string, which the caller
// puts wherever it already keeps things - a database column, a config row, a
// queue message. There is no master key and no file, so there is also no
// keystore to deploy alongside the application.
//
// The token is self-describing, and says so in its first field:
//
//   skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>     all hex after the count
//   skv1:<salt>:<iv>:<authTag>:<ciphertext>                  read only
//
// Carrying the version in the value itself is the one design decision here
// worth defending, and skv1 is the proof: it did carry a version, so this
// paragraph is about reading it rather than about a migration nobody can do.
// What skv1 lacked was a field for its iteration count, which is why its count
// is frozen at 100,000 forever and skv2's is not.

/** True if `value` is a token this library wrote, of either version. */
function isEncryptedValue(value) {
  return typeof value === 'string' &&
    (value.startsWith(`${VALUE_TOKEN_PREFIX}:`) || value.startsWith(`${VALUE_TOKEN_PREFIX_LEGACY}:`));
}

/**
 * Encrypts one string under a user key.
 *
 * A fresh random salt stretches the key (PBKDF2-SHA256) and a fresh random IV
 * feeds AES-256-GCM, so encrypting the same secret twice gives two different
 * tokens - which is what stops a database column from revealing which rows
 * share a value.
 *
 * `null`, `undefined` and `''` are returned unchanged, so this can be mapped
 * over a record without first sorting the empty fields out of it.
 *
 * Unlike a store, there is no master key here: every token is derived straight
 * from the user key, so the cost of the default 600,000 rounds is paid on every
 * single value. Encrypting a whole column is the case where that matters, and
 * the `iterations` option is there for it - the count is recorded in the token,
 * so decryption follows whatever was chosen.
 *
 * @param {string} plaintext
 * @param {string} userKey
 * @param {object} [options]
 * @param {number} [options.iterations]  default 600,000
 * @returns {string} an `skv2:` token
 */
function encryptValue(plaintext, userKey, options = {}) {
  if (plaintext === null || plaintext === undefined || plaintext === '') return plaintext;
  if (!userKey) {
    throw new KeystoreError(ErrorCodes.INVALID_ARGUMENT, 'encryptValue requires a userKey');
  }

  const iterations = options.iterations === undefined ? DEFAULT_KDF_ITERATIONS : options.iterations;
  if (!Number.isInteger(iterations) || iterations < MIN_KDF_ITERATIONS) {
    throw new KeystoreError(
      ErrorCodes.INVALID_ARGUMENT,
      `iterations must be a whole number of at least ${MIN_KDF_ITERATIONS}, not ${iterations}`
    );
  }

  const salt = randomSalt(TOKEN_SALT_LENGTH);
  const key = stretchPassword(userKey, salt, iterations);
  const { iv, authTag, data } = encrypt(plaintext, key, {
    ivLength: IV_LENGTH,
    aad: CONTEXT_TOKEN
  });

  return [VALUE_TOKEN_PREFIX, iterations, salt.toString(ENCODING), iv, authTag, data].join(':');
}

/**
 * Reverses {@link encryptValue}, for either token version.
 *
 * Anything that is not a token is returned unchanged, so a column part way
 * through being encrypted can be read with one call rather than a conditional
 * at every site. A token that is malformed, altered, or written under a
 * different user key throws - that case is never silently passed through,
 * because doing so would hand the caller ciphertext it believed was plaintext.
 *
 * @param {string} token
 * @param {string} userKey
 * @returns {string} the plaintext
 */
function decryptValue(token, userKey) {
  if (!isEncryptedValue(token)) return token;
  if (!userKey) {
    throw new KeystoreError(ErrorCodes.INVALID_ARGUMENT, 'decryptValue requires a userKey');
  }

  const parts = token.split(':');
  const legacy = parts[0] === VALUE_TOKEN_PREFIX_LEGACY;

  const expected = legacy ? VALUE_TOKEN_PARTS_LEGACY : VALUE_TOKEN_PARTS;
  if (parts.length !== expected) {
    throw new KeystoreError(
      ErrorCodes.BAD_TOKEN,
      `not a ${parts[0]} token: expected ${expected} colon-separated fields, found ${parts.length}`
    );
  }

  let iterations;
  let saltHex;
  let iv;
  let authTag;
  let data;

  if (legacy) {
    // skv1 has no iteration field, and every one ever written used 100,000.
    iterations = TOKEN_KDF_ITERATIONS_LEGACY;
    [, saltHex, iv, authTag, data] = parts;
  } else {
    let count;
    [, count, saltHex, iv, authTag, data] = parts;
    iterations = Number(count);
    if (!Number.isInteger(iterations) || iterations < 1) {
      throw new KeystoreError(
        ErrorCodes.BAD_TOKEN,
        `token iteration count is not a positive whole number: ${count}`
      );
    }
  }

  const key = stretchPassword(userKey, Buffer.from(saltHex, ENCODING), iterations);
  return decrypt({ iv, authTag, data }, key, {
    // skv1 predates additional authenticated data, and predates the 12-byte IV.
    // Both are read as they were written.
    aad: legacy ? null : CONTEXT_TOKEN,
    what: 'value'
  });
}

/**
 * The version of a token, for a caller deciding what to re-encrypt.
 *
 * @param {string} token
 * @returns {string|null} `'skv1'`, `'skv2'`, or null if it is not a token
 */
function tokenVersion(token) {
  if (!isEncryptedValue(token)) return null;
  return token.slice(0, token.indexOf(':'));
}

module.exports = {
  encryptValue,
  decryptValue,
  isEncryptedValue,
  tokenVersion,
  // Exported for the conformance generator, which has to write a legacy token
  // to have something to test reading one against.
  _legacy: { IV_LENGTH_LEGACY, VALUE_TOKEN_PREFIX_LEGACY, TOKEN_KDF_ITERATIONS_LEGACY }
};
