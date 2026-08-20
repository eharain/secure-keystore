//! Wire-format constants for the secure-keystore format.
//!
//! Nothing here is a tuning knob. These are the values that define what a store
//! written by this crate looks like, and changing one changes what the other
//! five implementations can read - which is why they live in one module rather
//! than scattered through the code that happens to use them.
//!
//! Two format versions appear throughout. 3.0 is what this build writes; 2.0 is
//! what earlier releases wrote and what this build still reads. Everywhere the
//! two differ, the legacy value is named `*_LEGACY` and the difference is a
//! parameter rather than a separate code path.

/// The store format stamped into every `master.json` this build writes.
pub const STORE_FORMAT_VERSION: &str = "3.0";

/// The older format this build still reads and, on a store already written that
/// way, still writes.
pub const STORE_FORMAT_LEGACY: &str = "2.0";

/// Identifies an export bundle, checked before anything is written to disk.
pub const BACKUP_FORMAT: &str = "secure-keystore-backup";

/// The bundle format this build writes and the highest it reads.
pub const BACKUP_VERSION: u32 = 1;

/// The current value-token prefix.
///
/// `skv2` records its own iteration count, which is the one thing `skv1` got
/// wrong: a token that cannot say how it was derived is a token whose parameters
/// can never change.
///
/// ```text
/// skv1:<salt>:<iv>:<authTag>:<ciphertext>
/// skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>
/// ```
pub const TOKEN_PREFIX: &str = "skv2";

/// The older token prefix, read but never written.
pub const TOKEN_PREFIX_LEGACY: &str = "skv1";

pub(crate) const TOKEN_PARTS: usize = 6;
pub(crate) const TOKEN_PARTS_LEGACY: usize = 5;

/// AES-256: a 32-byte key.
pub(crate) const KEY_LENGTH: usize = 32;

/// 12 bytes, which is what NIST SP 800-38D recommends for GCM and the only
/// length several platforms accept at all - .NET's `AesGcm` refuses anything
/// else, and it is what `Aes256Gcm` uses without a nonce-size parameter.
pub(crate) const IV_LENGTH: usize = 12;

/// The 16 bytes format 2.0 wrote, which needs the non-default nonce size.
pub(crate) const IV_LENGTH_LEGACY: usize = 16;

/// The GCM tag length, and the only one this format uses.
pub(crate) const AUTH_TAG_LENGTH: usize = 16;

/// What a new store stretches the user key with, following OWASP's 2023 guidance
/// for PBKDF2-HMAC-SHA256.
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// The floor below which the option is refused. Test suites run at this.
pub const MIN_ITERATIONS: u32 = 10_000;

/// Assumed for any 2.0 record written before the count was recorded.
pub(crate) const LEGACY_ITERATIONS: u32 = 100_000;

/// Fixed by the `skv1` layout, which has no field to record a count in.
pub(crate) const TOKEN_ITERATIONS_LEGACY: u32 = 100_000;

pub(crate) const STORE_SALT_LENGTH: usize = 32;
pub(crate) const VALUE_SALT_LENGTH: usize = 32;

/// 16, because the token carries its salt inline, in hex, in every stored value.
/// Fixed by the layout rather than by taste.
pub(crate) const TOKEN_SALT_LENGTH: usize = 16;

/// Domain-separation contexts, used as GCM additional authenticated data and,
/// for a value, as the HKDF info as well.
///
/// This is what closes the gap 2.0 had: there, the tag covered the ciphertext
/// and nothing else, so anyone who could write to a store could swap two value
/// files and both would decrypt - under each other's names.
pub(crate) const CONTEXT_MASTER: &str = "secure-keystore:v3:master";
pub(crate) const CONTEXT_VALUE_PREFIX: &str = "secure-keystore:v3:value:";
pub(crate) const CONTEXT_TOKEN: &str = "secure-keystore:v3:token";

/// The full context string binding a value to its key name.
pub(crate) fn value_context(key_name: &str) -> String {
    format!("{CONTEXT_VALUE_PREFIX}{key_name}")
}

/// Catalogue of stores: names and key names, no secrets.
pub(crate) const INDEX_FILE: &str = "index.json";

/// Per-store metadata and the encrypted master key.
pub(crate) const MASTER_FILE: &str = "master.json";

/// One authenticated-encrypted file per value.
pub(crate) const VALUE_EXTENSION: &str = ".enc";

/// Created under the working directory when no keystore directory is given.
pub const DEFAULT_KEYSTORE_DIRNAME: &str = ".keystore";

/// What `export_store` writes when given no path.
pub const DEFAULT_BACKUP_EXTENSION: &str = ".skb";

/// The name an input file uses for the master key, in every input format.
pub(crate) const MASTER_ENTRY_KEY: &str = "master";

/// Value filenames are a readable stem plus a hash of the key. The stem may
/// collide between two different keys; the hash is what keeps their files apart.
pub(crate) const FILENAME_STEM_LIMIT: usize = 64;
pub(crate) const FILENAME_HASH_LENGTH: usize = 8;

/// The major part of a version string, or 0 if it is not a number.
pub(crate) fn major_of(version: &str) -> u32 {
    version
        .split('.')
        .next()
        .and_then(|head| head.parse().ok())
        .unwrap_or(0)
}
