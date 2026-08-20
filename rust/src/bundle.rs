//! Export and import, as one JSON bundle.
//!
//! The contents are already encrypted, so a bundle is safe to put through a CI
//! artifact store or an `scp`, and useless to anyone who intercepts it without
//! the user key. It is pure JSON - no tar, no shell - so it behaves the same on
//! every platform.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Code, Error, Result};
use crate::format as fmt;

/// A whole store as one portable document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Always `secure-keystore-backup`. Checked before anything is written.
    pub format: String,
    /// The bundle format version.
    pub version: u32,
    /// The store this bundle came from.
    #[serde(rename = "storeName")]
    pub store_name: String,
    /// Every file in the store directory, verbatim.
    pub files: BTreeMap<String, String>,
}

/// Reads every file in a store directory into a bundle.
pub(crate) fn build_bundle(store_dir: &Path, store_name: &str) -> Result<Bundle> {
    let mut files = BTreeMap::new();

    let entries = std::fs::read_dir(store_dir).map_err(|_| {
        Error::new(
            Code::StoreNotFound,
            format!("could not read store directory {}", store_dir.display()),
        )
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        let content = std::fs::read_to_string(&path)
            .map_err(|_| Error::new(Code::StoreCorrupt, format!("could not read {name}")))?;

        files.insert(name, content);
    }

    Ok(Bundle {
        format: fmt::BACKUP_FORMAT.to_string(),
        version: fmt::BACKUP_VERSION,
        store_name: store_name.to_string(),
        files,
    })
}

/// Reads a bundle off disk and checks it is one of ours before any of it is
/// believed.
///
/// The checks are in the order that matters: a file that is not JSON, a JSON
/// document that is not a bundle, a bundle from a future version, and a bundle
/// with no `master.json` are four different mistakes and each says so.
pub(crate) fn read_bundle(backup_path: &Path) -> Result<Bundle> {
    let content = std::fs::read_to_string(backup_path).map_err(|_| {
        Error::new(
            Code::BadBackup,
            format!("backup file not found: {}", backup_path.display()),
        )
    })?;

    // Read into a loose value first, so a document that is JSON but not a bundle
    // is reported as such rather than as a deserialisation failure.
    let document: serde_json::Value = serde_json::from_str(&content).map_err(|_| {
        Error::new(
            Code::BadBackup,
            format!(
                "invalid backup file: {} is not readable as JSON",
                backup_path.display()
            ),
        )
    })?;

    let not_a_bundle = || {
        Error::new(
            Code::BadBackup,
            format!(
                "invalid backup file: {} is not a keystore bundle",
                backup_path.display()
            ),
        )
    };

    let object = document.as_object().ok_or_else(not_a_bundle)?;

    if object.get("format").and_then(|value| value.as_str()) != Some(fmt::BACKUP_FORMAT) {
        return Err(not_a_bundle());
    }
    if !object.get("files").map(|value| value.is_object()).unwrap_or(false) {
        return Err(not_a_bundle());
    }

    let version = object
        .get("version")
        .and_then(|value| value.as_u64())
        .unwrap_or(0) as u32;

    if version > fmt::BACKUP_VERSION {
        return Err(Error::new(
            Code::UnsupportedFormat,
            format!(
                "backup was written in bundle format {version}, and this build reads up to {}",
                fmt::BACKUP_VERSION
            ),
        ));
    }

    let bundle: Bundle = serde_json::from_value(document).map_err(|_| not_a_bundle())?;

    if !bundle.files.contains_key(fmt::MASTER_FILE) {
        return Err(Error::new(
            Code::BadBackup,
            format!("invalid backup: {} not found in bundle", fmt::MASTER_FILE),
        ));
    }

    Ok(bundle)
}

/// Writes a bundle's files into a target directory.
///
/// Every name is reduced to its base name first. A bundle is an untrusted file
/// that arrived over a wire, and `{"files": {"../../.ssh/authorized_keys": "..."}}`
/// is a bundle someone could write by hand.
///
/// `Path::file_name` follows the host's separator, so both are handled
/// explicitly - a bundle written on Windows must be as safe on Linux.
pub(crate) fn write_bundle(bundle: &Bundle, target_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(target_dir).map_err(|_| {
        Error::new(
            Code::BadBackup,
            format!("could not create {}", target_dir.display()),
        )
    })?;

    for (name, content) in &bundle.files {
        let safe = base_name(name);
        if safe.is_empty() || safe == "." || safe == ".." {
            continue;
        }

        std::fs::write(target_dir.join(safe), content)
            .map_err(|_| Error::new(Code::BadBackup, format!("could not write {safe}")))?;
    }

    Ok(())
}

/// Strips every directory component, whichever separator was used.
fn base_name(name: &str) -> &str {
    if let Some(index) = name.rfind(['/', '\\']) {
        return &name[index + 1..];
    }

    // A drive-relative name like "C:evil.txt" has no separator at all.
    let bytes = name.as_bytes();
    if bytes.len() > 1 && bytes[1] == b':' {
        return &name[2..];
    }

    name
}
