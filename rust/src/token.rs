//! Encryption with no store behind it.
//!
//! [`crate::Keystore`] owns a directory. These functions own nothing: they take
//! a secret and a user key and give back a string, which the caller puts
//! wherever it already keeps things - a database column, a config row, a queue
//! message. There is no master key and no file, so there is also no keystore to
//! deploy alongside the application.
//!
//! The token is self-describing, and says so in its first field:
//!
//! ```text
//! skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>     written and read
//! skv1:<salt>:<iv>:<authTag>:<ciphertext>                  read only
//! ```
//!
//! What `skv1` lacked was a field for its iteration count, which is why its count
//! is frozen at 100,000 forever and `skv2`'s is not.

use crate::crypto::{self, Encrypted};
use crate::error::{Code, Error, Result};
use crate::format as fmt;

/// Reports whether the value is a token this format defines, of either version.
pub fn is_encrypted_value(value: &str) -> bool {
    value.starts_with(&format!("{}:", fmt::TOKEN_PREFIX))
        || value.starts_with(&format!("{}:", fmt::TOKEN_PREFIX_LEGACY))
}

/// Returns `"skv2"`, `"skv1"`, or `None` if the value is not a token.
pub fn token_version(value: &str) -> Option<&str> {
    if !is_encrypted_value(value) {
        return None;
    }
    value.split(':').next()
}

/// Encrypts one string under a user key, with nothing on disk.
///
/// A fresh random salt stretches the key and a fresh random IV feeds
/// AES-256-GCM, so encrypting the same secret twice gives two different tokens -
/// which is what stops a database column from revealing which rows share a
/// value.
///
/// The empty string is returned unchanged, matching every other implementation,
/// so this can be mapped over a record without first sorting the empty fields out
/// of it.
///
/// `iterations` of `None` means [`fmt::DEFAULT_ITERATIONS`]. Unlike a store,
/// there is no master key here: every token is stretched straight from the user
/// key, so the default cost is paid on every single value. Encrypting a whole
/// column is the case where that matters, and this parameter is there for it -
/// the count is recorded in the token, so decryption follows whatever was chosen.
///
/// ```no_run
/// # use secure_keystore::{encrypt_value, decrypt_value};
/// let token = encrypt_value("sk_live_abc123", "user-key", None)?;
/// assert_eq!(decrypt_value(&token, "user-key")?, "sk_live_abc123");
/// # Ok::<(), secure_keystore::Error>(())
/// ```
pub fn encrypt_value(plaintext: &str, user_key: &str, iterations: Option<u32>) -> Result<String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }

    if user_key.is_empty() {
        return Err(Error::new(
            Code::InvalidArgument,
            "encrypt_value requires a user_key",
        ));
    }

    let count = iterations.unwrap_or(fmt::DEFAULT_ITERATIONS);
    if count < fmt::MIN_ITERATIONS {
        return Err(Error::new(
            Code::InvalidArgument,
            format!("iterations must be at least {}, not {count}", fmt::MIN_ITERATIONS),
        ));
    }

    let salt = crypto::random_bytes(fmt::TOKEN_SALT_LENGTH);
    let key = crypto::stretch_password(user_key, &salt, count);
    let record = crypto::encrypt(plaintext, &key, fmt::IV_LENGTH, fmt::CONTEXT_TOKEN)?;

    Ok(format!(
        "{}:{}:{}:{}:{}:{}",
        fmt::TOKEN_PREFIX,
        count,
        hex::encode(&salt),
        record.iv,
        record.auth_tag,
        record.data
    ))
}

/// Reverses [`encrypt_value`], for either token version.
///
/// Anything that is not a token is returned unchanged, so a column part way
/// through being encrypted can be read with one call rather than a conditional at
/// every site. A token that is malformed, altered, or written under a different
/// user key returns an error - that case is never silently passed through,
/// because doing so would hand the caller ciphertext it believed was plaintext.
pub fn decrypt_value(token: &str, user_key: &str) -> Result<String> {
    if !is_encrypted_value(token) {
        return Ok(token.to_string());
    }

    if user_key.is_empty() {
        return Err(Error::new(
            Code::InvalidArgument,
            "decrypt_value requires a user_key",
        ));
    }

    let parts: Vec<&str> = token.split(':').collect();
    let legacy = parts[0] == fmt::TOKEN_PREFIX_LEGACY;
    let expected = if legacy {
        fmt::TOKEN_PARTS_LEGACY
    } else {
        fmt::TOKEN_PARTS
    };

    if parts.len() != expected {
        return Err(Error::new(
            Code::BadToken,
            format!(
                "not a {} token: expected {expected} colon-separated fields, found {}",
                parts[0],
                parts.len()
            ),
        ));
    }

    let (iterations, salt_hex, record, aad) = if legacy {
        // skv1 has no iteration field, and every one ever written used 100,000.
        // It also predates additional authenticated data and the 12-byte IV;
        // both are read as they were written.
        (
            fmt::TOKEN_ITERATIONS_LEGACY,
            parts[1],
            Encrypted {
                iv: parts[2].to_string(),
                auth_tag: parts[3].to_string(),
                data: parts[4].to_string(),
            },
            "",
        )
    } else {
        let count: u32 = parts[1].parse().map_err(|_| {
            Error::new(
                Code::BadToken,
                format!("token iteration count is not a positive whole number: {:?}", parts[1]),
            )
        })?;

        if count < 1 {
            return Err(Error::new(
                Code::BadToken,
                format!("token iteration count is not a positive whole number: {:?}", parts[1]),
            ));
        }

        (
            count,
            parts[2],
            Encrypted {
                iv: parts[3].to_string(),
                auth_tag: parts[4].to_string(),
                data: parts[5].to_string(),
            },
            fmt::CONTEXT_TOKEN,
        )
    };

    let salt = hex::decode(salt_hex)
        .map_err(|_| Error::new(Code::BadToken, "token salt is not hex"))?;

    let key = crypto::stretch_password(user_key, &salt, iterations);
    crypto::decrypt(&record, &key, aad, "value")
}
