//! The store: a directory, and the operations on it.
//!
//! Two layers of encryption, and it is worth being precise about what the second
//! one buys. A user key unlocks the master key; the master key unlocks each
//! value. That is not defence in depth against a leaked user key - anyone holding
//! the user key reaches everything - it is what lets every value carry its own
//! salt and its own derived key, so no two values on disk share any material and
//! re-keying one value touches one file.
//!
//! The on-disk format is specified in SPEC.md at the root of the repository. This
//! build writes format 3.0 and reads 3.0 and 2.0. A store is never half one and
//! half the other: writing to a 2.0 store keeps writing 2.0 records until
//! [`Keystore::migrate`] moves the whole thing across.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::crypto::{self, Encrypted};
use crate::error::{Code, Error, Result};
use crate::format as fmt;
use crate::input::parse_input;
use crate::{bundle, token};

/// What [`Keystore::secure`] returns.
#[derive(Debug, Clone)]
pub struct SecureResult {
    /// The store that was written.
    pub store_name: String,
    /// Where it was written.
    pub store_dir: PathBuf,
    /// How many keys went in.
    pub total_keys: usize,
    /// Their names, in the order the input gave them.
    pub keys: Vec<String>,
}

/// What [`Keystore::set`] returns.
#[derive(Debug, Clone)]
pub struct SetResult {
    /// The key that was written.
    pub key: String,
    /// The store it went into.
    pub store_name: String,
    /// True if the key was new, false if an existing value was replaced.
    pub added: bool,
    /// The format the record was written in - a 2.0 store keeps taking 2.0 writes.
    pub format: String,
}

/// What [`Keystore::migrate`] returns.
#[derive(Debug, Clone)]
pub struct MigrateResult {
    /// The store that was rewritten.
    pub store_name: String,
    /// The format the store was in before.
    pub from: String,
    /// The format it is in now.
    pub to: String,
    /// Every key that was carried across.
    pub keys: Vec<String>,
    /// The PBKDF2 count it was rewritten with.
    pub iterations: u32,
}

/// Everything about a store that can be known without decrypting anything.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    /// The store name.
    pub name: String,
    /// Where it lives.
    pub path: PathBuf,
    /// The store format, `"3.0"` for anything this build writes.
    pub version: String,
    /// False if the store is still on 2.0 and would benefit from a migrate.
    pub current: bool,
    /// When it was first written.
    pub created: String,
    /// When it was last written.
    pub updated: String,
    /// The PBKDF2 count this store's user key is stretched with.
    pub iterations: u32,
    /// How many keys it holds.
    pub total_keys: usize,
    /// Their names.
    pub keys: Vec<String>,
    /// The input file it came from, for information only.
    pub source_file: String,
}

/// A store's `master.json`.
///
/// The whole document is kept, not just the fields this build knows about, so a
/// store written by a newer implementation is not silently downgraded by an older
/// one that happens to write to it. `serde_json` is built with `preserve_order`,
/// so a rewrite keeps the document's own key order too.
struct Metadata {
    raw: Map<String, Value>,
}

impl Metadata {
    /// Absent means 1.0, which is the same on-disk shape as 2.0 - 2.0 only added
    /// optional fields.
    fn format(&self) -> String {
        self.raw
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| !version.is_empty())
            .unwrap_or("1.0")
            .to_string()
    }

    fn is_legacy(&self) -> bool {
        fmt::major_of(&self.format()) < 3
    }

    /// Absent means the record predates the field, and every version that did so
    /// used 100,000.
    fn iterations(&self) -> u32 {
        self.raw
            .get("iterations")
            .and_then(Value::as_u64)
            .map(|count| count as u32)
            .unwrap_or(fmt::LEGACY_ITERATIONS)
    }

    fn iv_length(&self) -> usize {
        if self.is_legacy() {
            fmt::IV_LENGTH_LEGACY
        } else {
            fmt::IV_LENGTH
        }
    }

    fn master_aad(&self) -> String {
        if self.is_legacy() {
            String::new()
        } else {
            fmt::CONTEXT_MASTER.to_string()
        }
    }

    fn value_aad(&self, key_name: &str) -> String {
        if self.is_legacy() {
            String::new()
        } else {
            fmt::value_context(key_name)
        }
    }

    /// The `(key, file)` pairs, in order.
    fn entries(&self) -> Vec<(String, String)> {
        self.raw
            .get("entries")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        Some((
                            entry.get("key")?.as_str()?.to_string(),
                            entry.get("file")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A secure key-value store backed by a directory.
///
/// One instance binds one keystore directory and one set of options, validated
/// once in [`Keystore::new`] rather than on every call. It holds no secret of its
/// own - the user key is passed to each operation that needs it and is never
/// retained - so one instance built at start-up is safe to keep for the life of
/// the process.
///
/// ```no_run
/// # use secure_keystore::Keystore;
/// let store = Keystore::builder().build()?;
/// let api_key = store.get("api_key", &std::env::var("USER_KEY").unwrap(), Some("production"))?;
/// # Ok::<(), secure_keystore::Error>(())
/// ```
pub struct Keystore {
    keystore_dir: PathBuf,
    iterations: u32,
    logger: Option<Box<dyn Fn(&str) + Send + Sync>>,
}

/// Builds a [`Keystore`]. Every option has a default.
pub struct KeystoreBuilder {
    keystore_dir: Option<PathBuf>,
    iterations: u32,
    logger: Option<Box<dyn Fn(&str) + Send + Sync>>,
    create_dir: bool,
}

impl Default for KeystoreBuilder {
    fn default() -> Self {
        Self {
            keystore_dir: None,
            iterations: fmt::DEFAULT_ITERATIONS,
            logger: None,
            create_dir: true,
        }
    }
}

impl KeystoreBuilder {
    /// Where stores live. Defaults to `./.keystore`.
    pub fn keystore_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.keystore_dir = Some(dir.into());
        self
    }

    /// The PBKDF2 count the *user key* is stretched with, for new and migrated
    /// stores. Recorded in the store, so raising it never orphans one written
    /// before. It does not apply to value keys, which use HKDF and take no count.
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Called with one line of progress. Without one the crate prints nothing at
    /// all, which is the default and what a server wants.
    pub fn logger(mut self, logger: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.logger = Some(Box::new(logger));
        self
    }

    /// Create the keystore directory if it is absent. Default true.
    pub fn create_dir(mut self, create: bool) -> Self {
        self.create_dir = create;
        self
    }

    /// Validates the options and opens the keystore.
    pub fn build(self) -> Result<Keystore> {
        if self.iterations < fmt::MIN_ITERATIONS {
            return Err(Error::new(
                Code::InvalidOptions,
                format!(
                    "iterations must be at least {}, not {}",
                    fmt::MIN_ITERATIONS,
                    self.iterations
                ),
            ));
        }

        let keystore_dir = self.keystore_dir.unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_default()
                .join(fmt::DEFAULT_KEYSTORE_DIRNAME)
        });

        if self.create_dir {
            std::fs::create_dir_all(&keystore_dir).map_err(|_| {
                Error::new(
                    Code::InvalidOptions,
                    format!("could not create {}", keystore_dir.display()),
                )
            })?;
        }

        Ok(Keystore {
            keystore_dir,
            iterations: self.iterations,
            logger: self.logger,
        })
    }
}

impl Keystore {
    /// Starts building a keystore.
    pub fn builder() -> KeystoreBuilder {
        KeystoreBuilder::default()
    }

    /// The keystore directory this instance is bound to.
    pub fn dir(&self) -> &Path {
        &self.keystore_dir
    }

    /// The PBKDF2 count new and migrated stores are written with.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    fn log(&self, message: &str) {
        if let Some(logger) = &self.logger {
            logger(message);
        }
    }

    fn store_dir(&self, store_name: &str) -> PathBuf {
        self.keystore_dir.join(store_name)
    }

    /// An ISO 8601 stamp in the shape every implementation writes.
    fn now() -> String {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // Written by hand rather than pulling in `chrono`, for a crate that
        // otherwise needs no date handling at all.
        let millis = since_epoch.as_millis() as u64;
        let seconds = millis / 1000;
        let (days, rest) = (seconds / 86_400, seconds % 86_400);
        let (hour, minute, second) = (rest / 3600, (rest % 3600) / 60, rest % 60);
        let (year, month, day) = civil_from_days(days as i64);

        format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
            millis % 1000
        )
    }

    /// Reads and parses a store's `master.json`, or says which of the two is
    /// missing.
    fn read_metadata(&self, store_name: &str) -> Result<Metadata> {
        let dir = self.store_dir(store_name);
        if !dir.is_dir() {
            return Err(Error::new(
                Code::StoreNotFound,
                format!("keystore {store_name:?} not found"),
            ));
        }

        let master_path = dir.join(fmt::MASTER_FILE);
        let content = std::fs::read_to_string(&master_path).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!(
                    "keystore {store_name:?} has no {} - the directory exists but is not a store",
                    fmt::MASTER_FILE
                ),
            )
        })?;

        let raw: Map<String, Value> = serde_json::from_str(&content).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!(
                    "{} in keystore {store_name:?} is not readable JSON",
                    fmt::MASTER_FILE
                ),
            )
        })?;

        let metadata = Metadata { raw };

        if fmt::major_of(&metadata.format()) > fmt::major_of(fmt::STORE_FORMAT_VERSION) {
            return Err(Error::new(
                Code::UnsupportedFormat,
                format!(
                    "keystore {store_name:?} is in format {}, and this build reads up to {}",
                    metadata.format(),
                    fmt::STORE_FORMAT_VERSION
                ),
            ));
        }

        Ok(metadata)
    }

    fn write_metadata(&self, store_name: &str, metadata: &mut Metadata) -> Result<()> {
        metadata
            .raw
            .insert("updated".to_string(), json!(Self::now()));

        let encoded = serde_json::to_string_pretty(&metadata.raw)
            .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the metadata"))?;

        std::fs::write(self.store_dir(store_name).join(fmt::MASTER_FILE), encoded)
            .map_err(|_| Error::new(Code::StoreCorrupt, "could not write the metadata"))
    }

    /// Stretches the user key and decrypts the store's master key.
    fn unlock_master(&self, metadata: &Metadata, user_key: &str, store_name: &str) -> Result<String> {
        if user_key.is_empty() {
            return Err(Error::new(
                Code::InvalidArgument,
                "a user_key is required to read this store",
            ));
        }

        let salt_hex = metadata
            .raw
            .get("salt")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let salt = hex::decode(salt_hex).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!("keystore {store_name:?} has a malformed salt"),
            )
        })?;

        let master: Encrypted = metadata
            .raw
            .get("master")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or_else(|| {
                Error::new(
                    Code::StoreCorrupt,
                    format!("keystore {store_name:?} has no readable master key"),
                )
            })?;

        let user_derived = crypto::stretch_password(user_key, &salt, metadata.iterations());

        crypto::decrypt(&master, &user_derived, &metadata.master_aad(), "master key").map_err(
            |error| {
                if error.code == Code::BadUserKey {
                    Error::new(
                        Code::BadUserKey,
                        format!("wrong user key for keystore {store_name:?}"),
                    )
                } else {
                    error
                }
            },
        )
    }

    /// The key one value is encrypted under.
    ///
    /// In 3.0 that is HKDF from the master key, with the value's salt and a
    /// context naming the key - so a value file moved to another key's name
    /// derives a different key entirely. In 2.0 it was PBKDF2 over the master
    /// key, at the store's full iteration count, with nothing binding it to the
    /// name.
    fn value_key(
        master_key: &str,
        salt: &[u8],
        key_name: &str,
        metadata: &Metadata,
        record: &Map<String, Value>,
    ) -> Result<[u8; fmt::KEY_LENGTH]> {
        if metadata.is_legacy() {
            let count = record
                .get("iterations")
                .and_then(Value::as_u64)
                .map(|count| count as u32)
                .unwrap_or_else(|| metadata.iterations());

            return Ok(crypto::stretch_password(master_key, salt, count));
        }

        crypto::derive_from_key(master_key, salt, &fmt::value_context(key_name))
    }

    fn read_value(
        &self,
        store_name: &str,
        key_name: &str,
        file_name: &str,
        master_key: &str,
        metadata: &Metadata,
    ) -> Result<String> {
        let path = self.store_dir(store_name).join(file_name);

        let content = std::fs::read_to_string(&path).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!(
                    "key {key_name:?} is listed in {} but its file {file_name} is missing",
                    fmt::MASTER_FILE
                ),
            )
        })?;

        let record: Map<String, Value> = serde_json::from_str(&content).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!("the file for key {key_name:?} is not readable JSON"),
            )
        })?;

        let salt = hex::decode(record.get("salt").and_then(Value::as_str).unwrap_or_default())
            .map_err(|_| {
                Error::new(
                    Code::StoreCorrupt,
                    format!("the file for key {key_name:?} has a malformed salt"),
                )
            })?;

        let key = Self::value_key(master_key, &salt, key_name, metadata, &record)?;

        let data: Encrypted = record
            .get("data")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or_else(|| {
                Error::new(
                    Code::StoreCorrupt,
                    format!("the file for key {key_name:?} has no readable data"),
                )
            })?;

        crypto::decrypt(
            &data,
            &key,
            &metadata.value_aad(key_name),
            &format!("value for {key_name:?}"),
        )
    }

    fn write_value(
        &self,
        store_name: &str,
        file_name: &str,
        key_name: &str,
        value: &str,
        master_key: &str,
        metadata: &Metadata,
    ) -> Result<()> {
        let salt = crypto::random_bytes(fmt::VALUE_SALT_LENGTH);

        let mut record = Map::new();
        record.insert("salt".to_string(), json!(hex::encode(&salt)));

        // The iteration count only means anything to a 2.0 value, where the value
        // key is stretched from the master key. A 3.0 value derives with HKDF,
        // which takes no count, so writing one would record a number nothing
        // reads.
        if metadata.is_legacy() {
            record.insert("iterations".to_string(), json!(metadata.iterations()));
        }

        let key = Self::value_key(master_key, &salt, key_name, metadata, &record)?;
        let encrypted = crypto::encrypt(
            value,
            &key,
            metadata.iv_length(),
            &metadata.value_aad(key_name),
        )?;

        record.insert(
            "data".to_string(),
            serde_json::to_value(&encrypted)
                .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the value"))?,
        );

        let encoded = serde_json::to_string_pretty(&record)
            .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the value"))?;

        std::fs::write(self.store_dir(store_name).join(file_name), encoded)
            .map_err(|_| Error::new(Code::StoreCorrupt, format!("could not write {file_name}")))
    }

    /// Encrypts a key-value file into a store, in format 3.0.
    ///
    /// The input format follows the extension: `.json` an object, `.env` dotenv
    /// lines, anything else `key:value` lines with `master:` first. `None`
    /// defaults the store name to the input file's base name.
    ///
    /// Re-securing an existing store replaces it. The old `.enc` files go first,
    /// so a key dropped from the input does not linger on disk as an encrypted
    /// orphan that nothing references any more.
    pub fn secure(
        &self,
        input_file: &Path,
        user_key: &str,
        store_name: Option<&str>,
    ) -> Result<SecureResult> {
        if user_key.is_empty() {
            return Err(Error::new(Code::InvalidArgument, "secure requires a user_key"));
        }

        let parsed = parse_input(input_file)?;

        let master_key = parsed.master_key.filter(|key| !key.is_empty()).ok_or_else(|| {
            Error::new(
                Code::BadInput,
                r#"input must define a master key (e.g. "master:..." in .txt, "master=..." in .env, or a "master" property in .json)"#,
            )
        })?;

        if parsed.entries.is_empty() {
            return Err(Error::new(
                Code::BadInput,
                "no key-value entries found in input file",
            ));
        }

        let store_name = store_name
            .map(str::to_string)
            .unwrap_or_else(|| {
                input_file
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });

        let dir = self.store_dir(&store_name);
        std::fs::create_dir_all(&dir)
            .map_err(|_| Error::new(Code::StoreCorrupt, format!("could not create {}", dir.display())))?;

        if let Ok(existing) = std::fs::read_dir(&dir) {
            for entry in existing.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(fmt::VALUE_EXTENSION) || name == fmt::MASTER_FILE {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }

        let store_salt = crypto::random_bytes(fmt::STORE_SALT_LENGTH);
        let user_derived = crypto::stretch_password(user_key, &store_salt, self.iterations);
        let master = crypto::encrypt(&master_key, &user_derived, fmt::IV_LENGTH, fmt::CONTEXT_MASTER)?;

        let mut raw = Map::new();
        raw.insert("version".to_string(), json!(fmt::STORE_FORMAT_VERSION));
        raw.insert("created".to_string(), json!(Self::now()));
        raw.insert("salt".to_string(), json!(hex::encode(&store_salt)));
        raw.insert("iterations".to_string(), json!(self.iterations));
        raw.insert(
            "master".to_string(),
            serde_json::to_value(&master)
                .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the master key"))?,
        );
        raw.insert("entries".to_string(), json!([]));
        raw.insert(
            "sourceFile".to_string(),
            json!(input_file
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default()),
        );
        raw.insert("totalKeys".to_string(), json!(parsed.entries.len()));

        let mut metadata = Metadata { raw };
        let mut written = Vec::new();
        let mut keys = Vec::new();

        for entry in &parsed.entries {
            let file_name = crypto::safe_file_name(&entry.key);
            self.write_value(
                &store_name,
                &file_name,
                &entry.key,
                &entry.value,
                &master_key,
                &metadata,
            )?;
            written.push(json!({ "key": entry.key, "file": file_name }));
            keys.push(entry.key.clone());
        }

        metadata.raw.insert("entries".to_string(), Value::Array(written));

        self.write_metadata(&store_name, &mut metadata)?;
        self.update_index(&store_name, &metadata)?;
        self.log(&format!(
            "Secured {} keys in keystore {store_name:?} at {}",
            keys.len(),
            dir.display()
        ));

        Ok(SecureResult {
            store_name,
            store_dir: dir,
            total_keys: keys.len(),
            keys,
        })
    }

    /// Decrypts and returns one value.
    ///
    /// `None` searches every store. That is a convenience for a single-store
    /// setup and a trap for a multi-store one, where two stores may hold the same
    /// key name and the first match wins - name the store when it matters.
    pub fn get(&self, key: &str, user_key: &str, store_name: Option<&str>) -> Result<String> {
        let store_name = match store_name {
            Some(name) => name.to_string(),
            None => self.find_store_for_key(key)?,
        };

        let metadata = self.read_metadata(&store_name)?;

        let (key_name, file_name) = metadata
            .entries()
            .into_iter()
            .find(|(candidate, _)| candidate == key)
            .ok_or_else(|| {
                Error::new(
                    Code::KeyNotFound,
                    format!("key {key:?} not found in keystore {store_name:?}"),
                )
            })?;

        let master_key = self.unlock_master(&metadata, user_key, &store_name)?;
        self.read_value(&store_name, &key_name, &file_name, &master_key, &metadata)
    }

    /// Decrypts every value in a store.
    ///
    /// The user key is stretched once, not once per value, so this costs one
    /// PBKDF2 derivation however many keys the store holds.
    pub fn get_all(&self, user_key: &str, store_name: &str) -> Result<BTreeMap<String, String>> {
        let metadata = self.read_metadata(store_name)?;
        let master_key = self.unlock_master(&metadata, user_key, store_name)?;

        let mut values = BTreeMap::new();
        for (key_name, file_name) in metadata.entries() {
            let value = self.read_value(store_name, &key_name, &file_name, &master_key, &metadata)?;
            values.insert(key_name, value);
        }

        Ok(values)
    }

    /// Adds a key, or replaces the value of one already there.
    ///
    /// The replacement gets a fresh salt and a fresh IV, so an observer who kept
    /// the old file learns nothing by comparing it with the new one.
    ///
    /// On a store still in format 2.0 this writes a 2.0 record, so the store
    /// stays internally consistent. Run [`Keystore::migrate`] to move the whole
    /// store to 3.0.
    pub fn set(&self, key: &str, value: &str, user_key: &str, store_name: &str) -> Result<SetResult> {
        if key.is_empty() {
            return Err(Error::new(Code::InvalidArgument, "set requires a key"));
        }

        let mut metadata = self.read_metadata(store_name)?;
        let master_key = self.unlock_master(&metadata, user_key, store_name)?;

        let existing = metadata
            .entries()
            .into_iter()
            .find(|(candidate, _)| candidate == key);

        let added = existing.is_none();
        let file_name = existing
            .map(|(_, file)| file)
            .unwrap_or_else(|| crypto::safe_file_name(key));

        self.write_value(store_name, &file_name, key, value, &master_key, &metadata)?;

        if added {
            if let Some(Value::Array(entries)) = metadata.raw.get_mut("entries") {
                entries.push(json!({ "key": key, "file": file_name }));
                let total = entries.len();
                metadata.raw.insert("totalKeys".to_string(), json!(total));
            }
        }

        self.write_metadata(store_name, &mut metadata)?;
        self.update_index(store_name, &metadata)?;
        self.log(&format!(
            "Key {key:?} {} in keystore {store_name:?}",
            if added { "added" } else { "updated" }
        ));

        Ok(SetResult {
            key: key.to_string(),
            store_name: store_name.to_string(),
            added,
            format: metadata.format(),
        })
    }

    /// Rewrites a whole store in the current format.
    ///
    /// Every value is decrypted with the old parameters and re-encrypted with the
    /// new ones, under a fresh store salt and fresh per-value salts. The master
    /// key itself does not change, so nothing outside the store has to be told.
    ///
    /// A store already on the current format is re-encrypted rather than skipped,
    /// which is what makes this the way to raise a store's iteration count as well
    /// as its format.
    ///
    /// The rewrite is not atomic. Every value is decrypted before anything is
    /// written, so a wrong user key changes nothing; and every new value file is
    /// written before `master.json`, so an interruption leaves the store readable
    /// in its old format. Export first anyway.
    pub fn migrate(&self, store_name: &str, user_key: &str) -> Result<MigrateResult> {
        let metadata = self.read_metadata(store_name)?;
        let from = metadata.format();
        let master_key = self.unlock_master(&metadata, user_key, store_name)?;

        // Decrypt everything up front. If any value fails, the store is untouched.
        let mut values = Vec::new();
        for (key_name, file_name) in metadata.entries() {
            let value =
                self.read_value(store_name, &key_name, &file_name, &master_key, &metadata)?;
            values.push((key_name, value));
        }

        let store_salt = crypto::random_bytes(fmt::STORE_SALT_LENGTH);
        let user_derived = crypto::stretch_password(user_key, &store_salt, self.iterations);
        let master = crypto::encrypt(&master_key, &user_derived, fmt::IV_LENGTH, fmt::CONTEXT_MASTER)?;

        let mut rewritten = Metadata {
            raw: metadata.raw.clone(),
        };
        rewritten
            .raw
            .insert("version".to_string(), json!(fmt::STORE_FORMAT_VERSION));
        rewritten
            .raw
            .insert("salt".to_string(), json!(hex::encode(&store_salt)));
        rewritten
            .raw
            .insert("iterations".to_string(), json!(self.iterations));
        rewritten.raw.insert(
            "master".to_string(),
            serde_json::to_value(&master)
                .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the master key"))?,
        );
        rewritten
            .raw
            .insert("migrated".to_string(), json!(Self::now()));
        rewritten.raw.insert("entries".to_string(), json!([]));
        rewritten
            .raw
            .insert("totalKeys".to_string(), json!(values.len()));

        let dir = self.store_dir(store_name);
        let mut stale: Vec<String> = std::fs::read_dir(&dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(fmt::VALUE_EXTENSION))
                    .collect()
            })
            .unwrap_or_default();

        let mut written = Vec::new();
        let mut keys = Vec::new();

        for (key_name, value) in &values {
            let file_name = crypto::safe_file_name(key_name);
            self.write_value(store_name, &file_name, key_name, value, &master_key, &rewritten)?;
            written.push(json!({ "key": key_name, "file": file_name }));
            keys.push(key_name.clone());
            stale.retain(|name| name != &file_name);
        }

        rewritten
            .raw
            .insert("entries".to_string(), Value::Array(written));

        self.write_metadata(store_name, &mut rewritten)?;
        for name in stale {
            let _ = std::fs::remove_file(dir.join(name));
        }

        self.update_index(store_name, &rewritten)?;
        self.log(&if from == fmt::STORE_FORMAT_VERSION {
            format!(
                "Keystore {store_name:?} re-encrypted in format {} at {} iterations",
                fmt::STORE_FORMAT_VERSION,
                self.iterations
            )
        } else {
            format!(
                "Keystore {store_name:?} migrated from format {from} to {}",
                fmt::STORE_FORMAT_VERSION
            )
        });

        Ok(MigrateResult {
            store_name: store_name.to_string(),
            from,
            to: fmt::STORE_FORMAT_VERSION.to_string(),
            keys,
            iterations: self.iterations,
        })
    }

    /// Removes one key and its encrypted file.
    pub fn delete_key(&self, key: &str, store_name: &str) -> Result<()> {
        let mut metadata = self.read_metadata(store_name)?;

        let (_, file_name) = metadata
            .entries()
            .into_iter()
            .find(|(candidate, _)| candidate == key)
            .ok_or_else(|| {
                Error::new(
                    Code::KeyNotFound,
                    format!("key {key:?} not found in keystore {store_name:?}"),
                )
            })?;

        if let Some(Value::Array(entries)) = metadata.raw.get_mut("entries") {
            entries.retain(|entry| entry.get("key").and_then(Value::as_str) != Some(key));
            let total = entries.len();
            metadata.raw.insert("totalKeys".to_string(), json!(total));
        }

        let _ = std::fs::remove_file(self.store_dir(store_name).join(file_name));

        self.write_metadata(store_name, &mut metadata)?;
        self.update_index(store_name, &metadata)?;
        self.log(&format!("Key {key:?} deleted from keystore {store_name:?}"));

        Ok(())
    }

    /// The names of every store under this keystore directory.
    ///
    /// A directory counts as a store only if it holds a `master.json`, so an
    /// unrelated directory sitting alongside is not reported as one.
    pub fn list_stores(&self) -> Result<Vec<String>> {
        let Ok(entries) = std::fs::read_dir(&self.keystore_dir) else {
            return Ok(Vec::new());
        };

        let mut stores: Vec<String> = entries
            .flatten()
            .filter(|entry| entry.path().join(fmt::MASTER_FILE).is_file())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        stores.sort();
        Ok(stores)
    }

    /// The key names in a store.
    ///
    /// No user key, and none is needed: names live in metadata in the clear. That
    /// is a deliberate trade - it is what makes listing useful without a password
    /// - and it means a key name must not itself be a secret.
    pub fn list_keys(&self, store_name: &str) -> Result<Vec<String>> {
        Ok(self
            .read_metadata(store_name)?
            .entries()
            .into_iter()
            .map(|(key, _)| key)
            .collect())
    }

    /// Everything about a store that can be known without decrypting anything.
    pub fn store_info(&self, store_name: &str) -> Result<StoreInfo> {
        let metadata = self.read_metadata(store_name)?;

        let created = metadata
            .raw
            .get("created")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let updated = metadata
            .raw
            .get("updated")
            .and_then(Value::as_str)
            .unwrap_or(&created)
            .to_string();

        let keys: Vec<String> = metadata.entries().into_iter().map(|(key, _)| key).collect();

        Ok(StoreInfo {
            name: store_name.to_string(),
            path: self.store_dir(store_name),
            version: metadata.format(),
            current: !metadata.is_legacy(),
            created,
            updated,
            iterations: metadata.iterations(),
            total_keys: metadata
                .raw
                .get("totalKeys")
                .and_then(Value::as_u64)
                .map(|total| total as usize)
                .unwrap_or(keys.len()),
            keys,
            source_file: metadata
                .raw
                .get("sourceFile")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    /// Writes a store to a single portable bundle, `.skb` by default.
    ///
    /// The contents are already encrypted, so the bundle is safe to move through
    /// a CI artifact store or an `scp`.
    pub fn export_store(&self, store_name: &str, backup_path: Option<&Path>) -> Result<PathBuf> {
        self.read_metadata(store_name)?; // refuse early if it is not a store

        let path = match backup_path {
            Some(path) => path.to_path_buf(),
            None => {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();

                std::env::current_dir().unwrap_or_default().join(format!(
                    "{store_name}-backup-{stamp}{}",
                    fmt::DEFAULT_BACKUP_EXTENSION
                ))
            }
        };

        let built = bundle::build_bundle(&self.store_dir(store_name), store_name)?;
        let encoded = serde_json::to_string(&built)
            .map_err(|_| Error::new(Code::BadBackup, "could not serialise the bundle"))?;

        std::fs::write(&path, encoded)
            .map_err(|_| Error::new(Code::BadBackup, format!("could not write {}", path.display())))?;

        self.log(&format!(
            "Store {store_name:?} exported to {}",
            path.display()
        ));

        Ok(path)
    }

    /// Restores a bundle, under its own name or a new one.
    pub fn import_store(&self, backup_path: &Path, store_name: Option<&str>) -> Result<String> {
        let bundle = bundle::read_bundle(backup_path)?;

        let target = store_name
            .map(str::to_string)
            .filter(|name| !name.is_empty())
            .or_else(|| Some(bundle.store_name.clone()))
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                Error::new(
                    Code::BadBackup,
                    "cannot determine a target store name: the bundle names none and none was given",
                )
            })?;

        bundle::write_bundle(&bundle, &self.store_dir(&target))?;

        let metadata = self.read_metadata(&target)?;
        self.update_index(&target, &metadata)?;
        self.log(&format!("Store imported as {target:?}"));

        Ok(target)
    }

    /// Removes a store and its index entry. There is no undo; export first.
    pub fn delete_store(&self, store_name: &str) -> Result<()> {
        self.read_metadata(store_name)?; // refuse to delete a directory that is not a store

        std::fs::remove_dir_all(self.store_dir(store_name)).map_err(|_| {
            Error::new(
                Code::StoreCorrupt,
                format!("could not remove {}", self.store_dir(store_name).display()),
            )
        })?;

        let index_path = self.keystore_dir.join(fmt::INDEX_FILE);
        if let Ok(content) = std::fs::read_to_string(&index_path) {
            if let Ok(mut catalogue) = serde_json::from_str::<Map<String, Value>>(&content) {
                if let Some(Value::Object(stores)) = catalogue.get_mut("stores") {
                    stores.remove(store_name);
                }
                catalogue.insert("updated".to_string(), json!(Self::now()));
                if let Ok(encoded) = serde_json::to_string_pretty(&catalogue) {
                    let _ = std::fs::write(&index_path, encoded);
                }
            }
        }

        self.log(&format!("Keystore {store_name:?} deleted"));
        Ok(())
    }

    /// Instance sugar for [`token::encrypt_value`].
    pub fn encrypt_value(&self, plaintext: &str, user_key: &str, iterations: Option<u32>) -> Result<String> {
        token::encrypt_value(plaintext, user_key, iterations)
    }

    /// Instance sugar for [`token::decrypt_value`].
    pub fn decrypt_value(&self, value: &str, user_key: &str) -> Result<String> {
        token::decrypt_value(value, user_key)
    }

    /// Rewrites this store's entry in the keystore-wide catalogue.
    ///
    /// The catalogue holds names and counts and no secrets, which is what makes it
    /// safe to read without a user key - and what makes it merely a convenience:
    /// every operation reads the store's own `master.json` for anything that
    /// matters.
    fn update_index(&self, store_name: &str, metadata: &Metadata) -> Result<()> {
        let index_path = self.keystore_dir.join(fmt::INDEX_FILE);

        // A corrupt catalogue is not worth failing a write over - it holds
        // nothing that is not also in each store's own metadata. Rebuild it.
        let mut catalogue = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|content| serde_json::from_str::<Map<String, Value>>(&content).ok())
            .unwrap_or_default();

        if !catalogue.get("stores").map(Value::is_object).unwrap_or(false) {
            catalogue.insert("stores".to_string(), json!({}));
        }

        let keys: Vec<String> = metadata.entries().into_iter().map(|(key, _)| key).collect();

        if let Some(Value::Object(stores)) = catalogue.get_mut("stores") {
            stores.insert(
                store_name.to_string(),
                json!({
                    "version": metadata.format(),
                    "created": metadata.raw.get("created"),
                    "totalKeys": metadata.raw.get("totalKeys"),
                    "keys": keys,
                    "sourceFile": metadata.raw.get("sourceFile"),
                }),
            );
        }

        catalogue.insert("updated".to_string(), json!(Self::now()));

        let encoded = serde_json::to_string_pretty(&catalogue)
            .map_err(|_| Error::new(Code::StoreCorrupt, "could not serialise the catalogue"))?;

        std::fs::write(&index_path, encoded)
            .map_err(|_| Error::new(Code::StoreCorrupt, "could not write the catalogue"))
    }

    /// The first store holding this key.
    fn find_store_for_key(&self, key: &str) -> Result<String> {
        for store_name in self.list_stores()? {
            // A store we cannot read is not a store that holds the key.
            if let Ok(keys) = self.list_keys(&store_name) {
                if keys.iter().any(|candidate| candidate == key) {
                    return Ok(store_name);
                }
            }
        }

        Err(Error::new(
            Code::KeyNotFound,
            format!("key {key:?} not found in any keystore"),
        ))
    }
}

/// Days since the epoch to a civil (year, month, day).
///
/// Howard Hinnant's algorithm, which is exact and needs no table. Here so that
/// the crate can stamp a store without pulling in a date library it would use
/// for nothing else.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}
