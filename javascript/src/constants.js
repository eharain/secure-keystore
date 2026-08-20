'use strict';

// On-disk and on-the-wire constants for the secure-keystore format.
//
// Nothing here is a tuning knob. These are the values that define what a store
// written by this library looks like, and changing one changes what other
// implementations can read - which is why they live in one file rather than
// scattered through the code that happens to use them.
//
// Anything a caller is allowed to change lives in options.js instead.
//
// Two format versions appear throughout. 3.0 is what this build writes; 2.0 is
// what 1.x and 2.x wrote and what this build still reads. Everywhere the two
// differ, the legacy value is named `*_LEGACY` and the difference is a
// parameter rather than a separate code path.

// STORE_FORMAT_VERSION is the version stamped into every master.json this build
// writes. STORE_FORMAT_LEGACY is the older one it still reads and, on a store
// already written that way, still writes - so that a store is never half one
// format and half the other.
const STORE_FORMAT_VERSION = '3.0';
const STORE_FORMAT_LEGACY = '2.0';

// BACKUP_FORMAT and BACKUP_VERSION identify an export bundle. The format string
// is checked before anything is written to disk, so a file that merely happens
// to be JSON is refused rather than half-imported. A bundle carries whatever
// store format its files are in, so this did not change with 3.0.
const BACKUP_FORMAT = 'secure-keystore-backup';
const BACKUP_VERSION = 1;

// Value token layouts. `skv2` records its own iteration count, which is the one
// thing `skv1` got wrong: a token that cannot say how it was derived is a token
// whose parameters can never change.
//
//   skv1:<salt>:<iv>:<authTag>:<ciphertext>
//   skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>
const VALUE_TOKEN_PREFIX = 'skv2';
const VALUE_TOKEN_PARTS = 6;
const VALUE_TOKEN_PREFIX_LEGACY = 'skv1';
const VALUE_TOKEN_PARTS_LEGACY = 5;

// Cryptographic parameters. AES-256-GCM gives authenticated encryption, so a
// tampered file fails to decrypt rather than decrypting to something plausible.
const CIPHER_ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;   // bytes - AES-256
const KDF_DIGEST = 'sha256';

// IV_LENGTH is 12 in 3.0, which is what NIST SP 800-38D recommends for GCM and,
// more to the point, the only length several platforms will accept at all:
// .NET's AesGcm refuses anything else, and Go and Rust need a non-default
// constructor for it. IV_LENGTH_LEGACY is the 16 that 2.0 wrote.
const IV_LENGTH = 12;
const IV_LENGTH_LEGACY = 16;

// AUTH_TAG_LENGTH is the GCM default and the only length this format uses.
const AUTH_TAG_LENGTH = 16;

// DEFAULT_KDF_ITERATIONS is what a new store stretches the *user key* with, and
// follows OWASP's 2023 guidance for PBKDF2-HMAC-SHA256. It is a tunable - see
// options.js - and the count actually used is recorded in the store, so raising
// it never orphans a store written before.
const DEFAULT_KDF_ITERATIONS = 600000;
// MIN_KDF_ITERATIONS is the floor below which the option is refused. Test
// suites run at this; nothing else should.
const MIN_KDF_ITERATIONS = 10000;
// LEGACY_KDF_ITERATIONS is assumed for any 2.0 record written before the count
// was recorded. Every 1.x store used exactly this.
const LEGACY_KDF_ITERATIONS = 100000;
// TOKEN_KDF_ITERATIONS_LEGACY is fixed by the skv1 layout, which has no field
// to record a count in. skv2 records its own.
const TOKEN_KDF_ITERATIONS_LEGACY = 100000;

// Salt lengths. A store salt guards the key the user key is stretched into; a
// value salt is the HKDF salt for one value. Both are random per use, so two
// identical secrets never produce identical bytes on disk.
const STORE_SALT_LENGTH = 32;  // bytes
const VALUE_SALT_LENGTH = 32;  // bytes
// TOKEN_SALT_LENGTH is 16 because the token carries its salt inline, in hex, in
// every stored value. It is fixed by the token layout rather than by taste.
const TOKEN_SALT_LENGTH = 16;  // bytes

// Domain-separation contexts, used as GCM additional authenticated data and, for
// a value, as the HKDF info as well.
//
// This is what closes the gap 2.0 had: there, the tag covered the ciphertext and
// nothing else, so anyone who could write to a store could swap two value files
// and both would decrypt - under each other's names. Binding the key name means
// a swapped file derives a different key *and* fails its tag.
const CONTEXT_MASTER = 'secure-keystore:v3:master';
const CONTEXT_VALUE_PREFIX = 'secure-keystore:v3:value:';
const CONTEXT_TOKEN = 'secure-keystore:v3:token';

/** The full context string binding a value to its key name. */
function valueContext(keyName) {
  return CONTEXT_VALUE_PREFIX + String(keyName);
}

// ENCODING is how every binary field is written into JSON. Hex rather than
// base64 so a store file stays greppable and diffable.
const ENCODING = 'hex';

// Filenames inside a keystore directory.
const INDEX_FILE = 'index.json';    // catalogue of stores: names and key names, no secrets
const MASTER_FILE = 'master.json';  // per-store metadata and the encrypted master key
const VALUE_EXTENSION = '.enc';     // one authenticated-encrypted file per value

// DEFAULT_KEYSTORE_DIRNAME is the directory created under the working directory
// when no keystoreDir is given.
const DEFAULT_KEYSTORE_DIRNAME = '.keystore';

// DEFAULT_BACKUP_EXTENSION is what exportStore writes when given no path.
const DEFAULT_BACKUP_EXTENSION = '.skb';

// MASTER_ENTRY_KEY is the name an input file uses for the master key, in every
// input format.
const MASTER_ENTRY_KEY = 'master';

// FILENAME_STEM_LIMIT caps the readable part of a value filename. The hash
// suffix, not the stem, is what keeps two keys apart - the stem is there so a
// human can tell at a glance which file is which.
const FILENAME_STEM_LIMIT = 64;
const FILENAME_HASH_LENGTH = 8;  // hex characters

module.exports = {
  STORE_FORMAT_VERSION,
  STORE_FORMAT_LEGACY,
  BACKUP_FORMAT,
  BACKUP_VERSION,
  VALUE_TOKEN_PREFIX,
  VALUE_TOKEN_PARTS,
  VALUE_TOKEN_PREFIX_LEGACY,
  VALUE_TOKEN_PARTS_LEGACY,
  CIPHER_ALGORITHM,
  KEY_LENGTH,
  KDF_DIGEST,
  IV_LENGTH,
  IV_LENGTH_LEGACY,
  AUTH_TAG_LENGTH,
  DEFAULT_KDF_ITERATIONS,
  MIN_KDF_ITERATIONS,
  LEGACY_KDF_ITERATIONS,
  TOKEN_KDF_ITERATIONS_LEGACY,
  STORE_SALT_LENGTH,
  VALUE_SALT_LENGTH,
  TOKEN_SALT_LENGTH,
  CONTEXT_MASTER,
  CONTEXT_VALUE_PREFIX,
  CONTEXT_TOKEN,
  valueContext,
  ENCODING,
  INDEX_FILE,
  MASTER_FILE,
  VALUE_EXTENSION,
  DEFAULT_KEYSTORE_DIRNAME,
  DEFAULT_BACKUP_EXTENSION,
  MASTER_ENTRY_KEY,
  FILENAME_STEM_LIMIT,
  FILENAME_HASH_LENGTH
};
