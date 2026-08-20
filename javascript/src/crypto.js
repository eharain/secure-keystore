'use strict';

const crypto = require('crypto');
const {
  CIPHER_ALGORITHM,
  KEY_LENGTH,
  IV_LENGTH,
  KDF_DIGEST,
  ENCODING,
  VALUE_EXTENSION,
  FILENAME_STEM_LIMIT,
  FILENAME_HASH_LENGTH
} = require('./constants');
const { KeystoreError, ErrorCodes } = require('./errors');

// The cryptographic primitives, and nothing else.
//
// Every AES call in this library goes through this file, so there is exactly
// one place where an algorithm, an IV length or an encoding is chosen. The
// callers above deal in secrets and stores; none of them constructs a cipher.
//
// Two derivations, for two different jobs, which 2.0 conflated:
//
//   stretchPassword  a *password* into a key. Deliberately slow. Used once per
//                    store, on the user key, and on a value token.
//   deriveFromKey    a key into another key. Fast, because the input is already
//                    high-entropy key material and stretching it buys nothing.
//
// Running 600,000 PBKDF2 rounds on the master key once per value - which is
// what 2.0 did - costs seconds on a store of any size and adds no security the
// master key did not already have. That is the misuse HKDF exists to correct.

/** Random bytes, named so the call sites read as what they are. */
function randomSalt(length) {
  return crypto.randomBytes(length);
}

/**
 * PBKDF2-HMAC-SHA256: a password, stretched.
 *
 * `iterations` is a parameter rather than a constant because it is recorded
 * alongside whatever it derives - see SPEC.md. Deriving with a count that does
 * not match the one a record was written with produces a different key, and the
 * GCM tag then rejects it, which is the failure you want rather than the one
 * where it nearly works.
 *
 * @param {string|Buffer} password
 * @param {Buffer} salt
 * @param {number} iterations
 * @returns {Buffer} a 32-byte key
 */
function stretchPassword(password, salt, iterations) {
  return crypto.pbkdf2Sync(String(password), salt, iterations, KEY_LENGTH, KDF_DIGEST);
}

/**
 * HKDF-SHA256: one key into another, bound to a context.
 *
 * The input is the master key, which is already a strong secret, so there is
 * nothing to stretch - the job is separation, not hardening. `info` carries the
 * context that separates them, and for a value that context contains the key
 * name, which is half of what stops two value files being swapped. The other
 * half is the same string passed as GCM additional data.
 *
 * @param {string|Buffer} key   high-entropy input key material
 * @param {Buffer} salt
 * @param {string} info         the context this derived key is for
 * @returns {Buffer} a 32-byte key
 */
function deriveFromKey(key, salt, info) {
  const derived = crypto.hkdfSync(
    KDF_DIGEST,
    Buffer.from(String(key), 'utf8'),
    salt,
    Buffer.from(info, 'utf8'),
    KEY_LENGTH
  );
  return Buffer.from(derived);
}

/**
 * AES-256-GCM with a fresh random IV, so the same plaintext under the same key
 * never produces the same bytes twice.
 *
 * @param {string} plaintext
 * @param {Buffer} key                 32 bytes
 * @param {object} [options]
 * @param {number} [options.ivLength]  12 in format 3.0, 16 in the 2.0 records
 *                                     this build still writes into 2.0 stores
 * @param {string|null} [options.aad]  additional authenticated data - the
 *                                     context string, or null in 2.0
 * @returns {{iv: string, authTag: string, data: string}} all hex
 */
function encrypt(plaintext, key, options = {}) {
  const ivLength = options.ivLength || IV_LENGTH;
  const aad = options.aad || null;

  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, key, iv);
  if (aad !== null) cipher.setAAD(Buffer.from(aad, 'utf8'));

  let data = cipher.update(String(plaintext), 'utf8', ENCODING);
  data += cipher.final(ENCODING);

  return {
    iv: iv.toString(ENCODING),
    authTag: cipher.getAuthTag().toString(ENCODING),
    data
  };
}

/**
 * Reverses {@link encrypt}, and translates the failure.
 *
 * GCM cannot tell a wrong key from tampered bytes from mismatched additional
 * data - all three are a tag that does not verify - and node reports any of
 * them as `Unsupported state or unable to authenticate data`, which tells a
 * caller nothing. They become BAD_USER_KEY here, with the original attached as
 * `cause` for anyone who wants it.
 *
 * @param {{iv: string, authTag: string, data: string}} encrypted
 * @param {Buffer} key
 * @param {object} [options]
 * @param {string|null} [options.aad]  must match what encrypt was given
 * @param {string} [options.what]      what is being decrypted, for the message
 * @returns {string} the plaintext
 * @throws {KeystoreError} with code BAD_USER_KEY
 */
function decrypt(encrypted, key, options = {}) {
  const aad = options.aad || null;
  const what = options.what || 'value';

  if (!encrypted || typeof encrypted.iv !== 'string' ||
      typeof encrypted.authTag !== 'string' || typeof encrypted.data !== 'string') {
    throw new KeystoreError(
      ErrorCodes.STORE_CORRUPT,
      `the encrypted ${what} is missing its iv, authTag or data`
    );
  }

  try {
    const decipher = crypto.createDecipheriv(
      CIPHER_ALGORITHM,
      key,
      Buffer.from(encrypted.iv, ENCODING)
    );
    decipher.setAuthTag(Buffer.from(encrypted.authTag, ENCODING));
    if (aad !== null) decipher.setAAD(Buffer.from(aad, 'utf8'));

    let plaintext = decipher.update(encrypted.data, ENCODING, 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
  } catch (cause) {
    throw new KeystoreError(
      ErrorCodes.BAD_USER_KEY,
      `could not decrypt the ${what}: the key is wrong, or the stored bytes have been altered`,
      { cause }
    );
  }
}

/**
 * A filesystem-safe, collision-resistant filename for a key.
 *
 * The stem is for humans, so it is the key with anything unsafe replaced -
 * which neutralises `../`, drive letters and the characters Windows refuses.
 * Sanitising alone would map `a/b` and `a_b` onto one file, so the real
 * identity is the hash suffix; the stem is only a label.
 *
 * Both the substitution and the truncation are done over **UTF-8 bytes**, which
 * SPEC.md fixes and which is the only definition every language agrees on. A
 * JavaScript string is UTF-16, so replacing per character would turn a four-
 * character Cyrillic key into four underscores where every other implementation
 * writes eight - the same store, named differently depending on who wrote it.
 * A multi-byte character straddling the 64-byte limit is cut, but the name is a
 * label and the hash is the identity, so a mangled label costs nothing.
 *
 * @param {string} key
 * @returns {string} e.g. `api_key-3f2a1b9c.enc`
 */
function safeFileName(key) {
  const raw = String(key);
  const bytes = Buffer.from(raw, 'utf8').subarray(0, FILENAME_STEM_LIMIT);

  let stem = '';
  for (const byte of bytes) {
    const character = String.fromCharCode(byte);
    stem += /[A-Za-z0-9._-]/.test(character) ? character : '_';
  }

  const hash = crypto.createHash('sha256').update(raw, 'utf8').digest('hex').slice(0, FILENAME_HASH_LENGTH);
  return `${stem}-${hash}${VALUE_EXTENSION}`;
}

module.exports = { randomSalt, stretchPassword, deriveFromKey, encrypt, decrypt, safeFileName };
