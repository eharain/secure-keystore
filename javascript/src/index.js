'use strict';

// secure-keystore: encrypted secrets at rest, with no service to run.
//
// Two ways in, and they are meant to be used for different things:
//
//  1. A store. A directory of encrypted values that a user key unlocks. The
//     store owns the master key, one salt per value, and a catalogue - so an
//     application deploys a directory and reads secrets out of it at run time.
//     That is `SecureKeystore`.
//  2. A token. One string in, one string out, nothing on disk. The application
//     already has somewhere to put it - a database column, a config row - and
//     only wants the value unreadable while it sits there. That is
//     `encryptValue` / `decryptValue`.
//
// Both use the same primitives: PBKDF2-HMAC-SHA256 to derive, AES-256-GCM to
// encrypt, a fresh random salt and IV every time. The wire and disk formats are
// specified in SPEC.md at the root of this repository, and the other language
// implementations read and write the same bytes.
//
//   const { SecureKeystore, encryptValue } = require('@tech-style/secure-keystore');
//
//   const store = new SecureKeystore();
//   store.secure('./keys.env', process.env.USER_KEY, 'production');
//   const apiKey = store.get('api_key', process.env.USER_KEY, 'production');

const SecureKeystore = require('./store');
const { encryptValue, decryptValue, isEncryptedValue, tokenVersion } = require('./value');
const { KeystoreError, ErrorCodes } = require('./errors');
const { defaultOptions } = require('./options');
const { Formats } = require('./parse');
const {
  STORE_FORMAT_VERSION,
  STORE_FORMAT_LEGACY,
  BACKUP_VERSION,
  VALUE_TOKEN_PREFIX,
  CIPHER_ALGORITHM,
  KDF_DIGEST,
  DEFAULT_KDF_ITERATIONS,
  IV_LENGTH
} = require('./constants');

/**
 * VERSION is the version of this implementation, which is not the same thing as
 * the version of the store format (STORE_FORMAT_VERSION) or of the value token
 * (VALUE_TOKEN_PREFIX). A release may bump this and leave both of those alone -
 * and usually does.
 */
const VERSION = '3.0.1';

/**
 * ALGORITHMS describes what this build actually does, in one object, so that a
 * caller who has to write it down in a compliance document does not have to
 * read the source to find out.
 */
const ALGORITHMS = Object.freeze({
  cipher: CIPHER_ALGORITHM,
  ivBytes: IV_LENGTH,
  /** How the *user key* - a password - is stretched. Deliberately slow. */
  passwordKdf: 'pbkdf2-hmac-sha256',
  defaultIterations: DEFAULT_KDF_ITERATIONS,
  /** How a value key is derived from the master key. Fast, and correctly so. */
  keyKdf: 'hkdf-sha256',
  digest: KDF_DIGEST,
  keyBits: 256,
  /** Whether a value is cryptographically bound to its key name. */
  bindsKeyName: true
});

// The default export stays the class, so `require('@tech-style/secure-keystore')`
// keeps working exactly as it did before the package was split into modules.
// The named exports hang off it.
module.exports = SecureKeystore;

module.exports.SecureKeystore = SecureKeystore;
module.exports.default = SecureKeystore;

module.exports.encryptValue = encryptValue;
module.exports.decryptValue = decryptValue;
module.exports.isEncryptedValue = isEncryptedValue;
module.exports.tokenVersion = tokenVersion;

module.exports.KeystoreError = KeystoreError;
module.exports.ErrorCodes = ErrorCodes;
module.exports.defaultOptions = defaultOptions;
module.exports.Formats = Formats;

module.exports.VERSION = VERSION;
module.exports.ALGORITHMS = ALGORITHMS;
module.exports.STORE_FORMAT_VERSION = STORE_FORMAT_VERSION;
module.exports.STORE_FORMAT_LEGACY = STORE_FORMAT_LEGACY;
module.exports.BACKUP_VERSION = BACKUP_VERSION;
module.exports.VALUE_TOKEN_PREFIX = VALUE_TOKEN_PREFIX;
