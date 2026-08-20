//! The cryptographic primitives, and nothing else.
//!
//! Every AES call in this crate goes through this module, so there is exactly
//! one place where an algorithm, an IV length or an encoding is chosen.
//!
//! Two derivations, for two different jobs, which format 2.0 conflated:
//!
//! - [`stretch_password`] turns a *password* into a key. Deliberately slow. Used
//!   once per store, on the user key, and on every value token.
//! - [`derive_from_key`] turns a key into another key. Fast, because the input is
//!   already high-entropy key material and stretching it buys nothing.
//!
//! Running 600,000 PBKDF2 rounds on the master key once per value - which 2.0
//! did - costs seconds on a store of any size and adds no security the master
//! key did not already have. That is the misuse HKDF exists to correct.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{AesGcm, Aes256Gcm, Nonce};
use aes_gcm::aes::Aes256;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Code, Error, Result};
use crate::format as fmt;

/// AES-256-GCM with the 16-byte nonce format 2.0 used.
///
/// `Aes256Gcm` fixes the nonce at 12 bytes, which is what 3.0 writes and what
/// every platform accepts. Reading a 2.0 store needs the other size spelled out,
/// which is exactly the friction 3.0 exists to remove.
type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// One AES-GCM result, as it appears in a store file. Every field is lowercase
/// hex.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Encrypted {
    pub iv: String,
    #[serde(rename = "authTag")]
    pub auth_tag: String,
    pub data: String,
}

/// Random bytes from the system source.
pub(crate) fn random_bytes(length: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer
}

/// PBKDF2-HMAC-SHA256: a password, stretched.
///
/// The count is a parameter rather than a constant because it is recorded
/// alongside whatever it derives. Deriving with a count that does not match the
/// one a record was written with produces a different key, and the GCM tag then
/// rejects it - which is the failure you want rather than the one where it
/// nearly works.
pub(crate) fn stretch_password(password: &str, salt: &[u8], iterations: u32) -> [u8; fmt::KEY_LENGTH] {
    let mut key = [0u8; fmt::KEY_LENGTH];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
    key
}

/// HKDF-SHA256: one key into another, bound to a context.
///
/// The input is the master key, which is already a strong secret, so there is
/// nothing to stretch - the job is separation, not hardening. `info` carries the
/// context that separates them, and for a value that context contains the key
/// name, which is half of what stops two value files being swapped. The other
/// half is the same string passed as GCM additional data.
pub(crate) fn derive_from_key(key: &str, salt: &[u8], info: &str) -> Result<[u8; fmt::KEY_LENGTH]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), key.as_bytes());
    let mut derived = [0u8; fmt::KEY_LENGTH];

    hkdf.expand(info.as_bytes(), &mut derived)
        .map_err(|_| Error::new(Code::InvalidArgument, "could not derive a value key"))?;

    Ok(derived)
}

/// Seal a plaintext under a fresh random IV, so the same plaintext under the
/// same key never produces the same bytes twice.
///
/// `aad` is empty for a format 2.0 record, which bound nothing.
pub(crate) fn encrypt(plaintext: &str, key: &[u8], iv_length: usize, aad: &str) -> Result<Encrypted> {
    let iv = random_bytes(iv_length);
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: aad.as_bytes(),
    };

    // Both `encrypt` calls append the tag to the ciphertext; the format stores
    // them as separate hex fields.
    let sealed = if iv_length == fmt::IV_LENGTH {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::new(Code::InvalidArgument, "could not build the cipher"))?;
        cipher.encrypt(Nonce::from_slice(&iv), payload)
    } else {
        let cipher = Aes256Gcm16::new_from_slice(key)
            .map_err(|_| Error::new(Code::InvalidArgument, "could not build the cipher"))?;
        cipher.encrypt(iv.as_slice().into(), payload)
    }
    .map_err(|_| Error::new(Code::InvalidArgument, "encryption failed"))?;

    let split = sealed.len() - fmt::AUTH_TAG_LENGTH;

    Ok(Encrypted {
        iv: hex::encode(&iv),
        auth_tag: hex::encode(&sealed[split..]),
        data: hex::encode(&sealed[..split]),
    })
}

/// Reverse [`encrypt`], and translate the failure.
///
/// GCM cannot tell a wrong key from tampered bytes from mismatched additional
/// data - all three are a tag that does not verify - and `aes-gcm` reports any of
/// them as one opaque `Error`, which tells a caller nothing. All three become
/// [`Code::BadUserKey`] here.
pub(crate) fn decrypt(record: &Encrypted, key: &[u8], aad: &str, what: &str) -> Result<String> {
    let malformed = || Error::new(Code::StoreCorrupt, format!("the encrypted {what} has a malformed hex field"));

    let iv = hex::decode(&record.iv).map_err(|_| malformed())?;
    let tag = hex::decode(&record.auth_tag).map_err(|_| malformed())?;
    let data = hex::decode(&record.data).map_err(|_| malformed())?;

    if iv.is_empty() {
        return Err(Error::new(
            Code::StoreCorrupt,
            format!("the encrypted {what} has an empty iv"),
        ));
    }

    let mut sealed = data;
    sealed.extend_from_slice(&tag);

    let payload = Payload {
        msg: &sealed,
        aad: aad.as_bytes(),
    };

    let opened = if iv.len() == fmt::IV_LENGTH {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::new(Code::InvalidArgument, "could not build the cipher"))?;
        cipher.decrypt(Nonce::from_slice(&iv), payload)
    } else if iv.len() == fmt::IV_LENGTH_LEGACY {
        let cipher = Aes256Gcm16::new_from_slice(key)
            .map_err(|_| Error::new(Code::InvalidArgument, "could not build the cipher"))?;
        cipher.decrypt(iv.as_slice().into(), payload)
    } else {
        return Err(Error::new(
            Code::StoreCorrupt,
            format!("the encrypted {what} has an iv of {} bytes, which this format never writes", iv.len()),
        ));
    }
    .map_err(|_| {
        Error::new(
            Code::BadUserKey,
            format!("could not decrypt the {what}: the key is wrong, or the stored bytes have been altered"),
        )
    })?;

    String::from_utf8(opened)
        .map_err(|_| Error::new(Code::StoreCorrupt, format!("the decrypted {what} is not valid UTF-8")))
}

/// A filesystem-safe, collision-resistant filename for a key.
///
/// The stem is for humans, so it is the key with anything unsafe replaced -
/// which neutralises `../`, drive letters and the characters Windows refuses.
/// Sanitising alone would map `a/b` and `a_b` onto one file, so the real
/// identity is the hash suffix; the stem is only a label.
///
/// The stem is built from UTF-8 bytes and truncated by bytes, which SPEC.md
/// fixes and which is the only definition every language agrees on. A multi-byte
/// character straddling the limit is cut, but the name is a label and the hash is
/// the identity, so a mangled label costs nothing.
pub(crate) fn safe_file_name(key: &str) -> String {
    let raw = key.as_bytes();

    let stem: String = raw
        .iter()
        .take(fmt::FILENAME_STEM_LIMIT)
        .map(|&byte| {
            let character = byte as char;
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();

    let digest = hex::encode(Sha256::digest(raw));

    format!(
        "{stem}-{}{}",
        &digest[..fmt::FILENAME_HASH_LENGTH],
        fmt::VALUE_EXTENSION
    )
}
