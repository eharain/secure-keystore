//! Encrypted secrets at rest, with no service to run.
//!
//! Two ways in, for different things:
//!
//! 1. **A store.** A directory of encrypted values that one user key opens. The
//!    store owns a master key, one salt per value, and a catalogue - so an
//!    application deploys a directory and reads secrets out of it at run time.
//!    That is [`Keystore`].
//! 2. **A token.** One string in, one string out, nothing on disk. The
//!    application already has somewhere to put it - a database column, a config
//!    row - and only wants the value unreadable while it sits there. That is
//!    [`encrypt_value`] and [`decrypt_value`].
//!
//! Both use the same primitives: AES-256-GCM to encrypt, PBKDF2-HMAC-SHA256 to
//! stretch the user key, HKDF-SHA256 to derive a value key from the master key. A
//! fresh random salt and IV every time.
//!
//! ```no_run
//! use secure_keystore::Keystore;
//!
//! let store = Keystore::builder().build()?;
//! store.secure(std::path::Path::new("./keys.env"), "user-key", Some("production"))?;
//! let api_key = store.get("api_key", "user-key", Some("production"))?;
//! # Ok::<(), secure_keystore::Error>(())
//! ```
//!
//! # Which KDF, and why two
//!
//! A user key is a password, so it is stretched: deliberately slow, 600,000
//! rounds by default. A master key is not a password - it is already a strong
//! secret - so value keys come from HKDF, which is fast. Stretching the master
//! key once per value, which format 2.0 did, costs seconds on a store of any size
//! and buys nothing the master key did not already have.
//!
//! # The format
//!
//! The on-disk format is specified in SPEC.md at the root of the repository, and
//! this crate reads and writes the same bytes as the JavaScript, Go, .NET, Python
//! and PHP ones. That is not a claim but a test: all six run the same conformance
//! corpus, and this crate's copy is in `tests/conformance.rs`.
//!
//! This build writes format 3.0 and reads 3.0 and 2.0. A 2.0 store keeps taking
//! 2.0 writes until [`Keystore::migrate`] moves the whole thing across, so a
//! store is never half one format and half the other.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod bundle;
mod crypto;
mod error;
mod format;
mod input;
mod keystore;
mod token;

pub use bundle::Bundle;
pub use error::{Code, Error, Result};
pub use format::{
    BACKUP_VERSION, DEFAULT_ITERATIONS, DEFAULT_BACKUP_EXTENSION, DEFAULT_KEYSTORE_DIRNAME,
    MIN_ITERATIONS, STORE_FORMAT_LEGACY, STORE_FORMAT_VERSION, TOKEN_PREFIX, TOKEN_PREFIX_LEGACY,
};
pub use input::{format_for, parse_input, parse_text, Entry, InputFormat, ParsedInput};
pub use keystore::{Keystore, KeystoreBuilder, MigrateResult, SecureResult, SetResult, StoreInfo};
pub use token::{decrypt_value, encrypt_value, is_encrypted_value, token_version};

/// The version of this implementation, which is not the same thing as the
/// version of the store format ([`STORE_FORMAT_VERSION`]).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
