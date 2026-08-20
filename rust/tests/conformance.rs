//! The shared corpus, run against this implementation.
//!
//! The corpus was written by the JavaScript implementation. Nothing here has
//! ever seen that code - this crate was written against SPEC.md - so passing
//! this file is the whole cross-language claim, tested rather than asserted.
//!
//! It cannot be a comparison of encoders: every write in this format draws a
//! fresh salt and a fresh IV, so two implementations encrypting the same secret
//! never produce the same bytes. What is pinned is the other direction - these
//! bytes, under this key, must come back as this plaintext - plus the refusals,
//! which matter just as much. An implementation that accepts a tampered token is
//! not conforming however well it handles the happy path.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use secure_keystore::{decrypt_value, is_encrypted_value, token_version, Keystore};
use serde::Deserialize;

#[derive(Deserialize)]
struct StoreCase {
    name: String,
    #[serde(rename = "keystorePath")]
    keystore_path: String,
    format: String,
    expected: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct TokenCase {
    name: String,
    version: Option<String>,
    token: String,
    expected: String,
}

#[derive(Deserialize)]
struct BundleCase {
    name: String,
    path: String,
    #[serde(rename = "importAs")]
    import_as: String,
    expected: BTreeMap<String, String>,
    #[serde(rename = "mustNotCreate", default)]
    must_not_create: Vec<String>,
    #[serde(rename = "mustCreateInsideStore", default)]
    must_create_inside_store: Vec<String>,
}

#[derive(Deserialize)]
struct TokenRefusal {
    name: String,
    token: String,
    #[serde(rename = "userKey")]
    user_key: String,
    code: String,
}

#[derive(Deserialize)]
struct BundleRefusal {
    name: String,
    path: String,
    code: String,
}

#[derive(Deserialize)]
struct StoreRefusal {
    name: String,
    #[serde(rename = "keystorePath")]
    keystore_path: String,
    store: String,
    code: String,
}

#[derive(Deserialize)]
struct Refusals {
    tokens: Vec<TokenRefusal>,
    bundles: Vec<BundleRefusal>,
    stores: Vec<StoreRefusal>,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "userKey")]
    user_key: String,
    #[serde(rename = "masterKey")]
    master_key: String,
    iterations: u32,
    stores: Vec<StoreCase>,
    tokens: Vec<TokenCase>,
    bundles: Vec<BundleCase>,
    refusals: Refusals,
}

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate has a parent directory")
        .join("conformance")
}

/// Loads the manifest, or `None` when the corpus has not been generated.
fn manifest() -> Option<Manifest> {
    let path = corpus_dir().join("manifest.json");
    let content = std::fs::read_to_string(path).ok()?;

    Some(serde_json::from_str(&content).expect("the corpus manifest is readable"))
}

fn fixture(relative: &str) -> PathBuf {
    let mut path = corpus_dir().join("fixtures");
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

/// Opens a corpus keystore without creating anything.
fn reader(keystore_path: &str) -> Keystore {
    Keystore::builder()
        .keystore_dir(fixture(keystore_path))
        .iterations(secure_keystore::MIN_ITERATIONS)
        .create_dir(false)
        .build()
        .expect("the corpus keystore opens")
}

fn scratch(name: &str, iterations: u32) -> (PathBuf, Keystore) {
    let dir = std::env::temp_dir().join(format!(
        "secure-keystore-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    let store = Keystore::builder()
        .keystore_dir(dir.join(".keystore"))
        .iterations(iterations)
        .build()
        .expect("a scratch keystore opens");

    (dir, store)
}

macro_rules! corpus {
    ($manifest:ident) => {
        match manifest() {
            Some(loaded) => loaded,
            None => {
                eprintln!("no conformance corpus - run: node conformance/generate.js");
                return;
            }
        }
    };
}

#[test]
fn every_store_decrypts_to_the_expected_values() {
    let manifest = corpus!(manifest);
    assert!(!manifest.stores.is_empty());

    for store in &manifest.stores {
        let keystore = reader(&store.keystore_path);

        let info = keystore.store_info(&store.name).expect("store info");
        assert_eq!(info.version, store.format, "{}", store.name);

        let values = keystore
            .get_all(&manifest.user_key, &store.name)
            .unwrap_or_else(|error| panic!("{}: {error}", store.name));

        assert_eq!(values, store.expected, "{}", store.name);

        // And one at a time, which takes a different path through the code.
        for (key, expected) in &store.expected {
            let value = keystore
                .get(key, &manifest.user_key, Some(&store.name))
                .unwrap_or_else(|error| panic!("{}/{key}: {error}", store.name));
            assert_eq!(&value, expected);
        }
    }
}

#[test]
fn every_token_decrypts_to_the_expected_value() {
    let manifest = corpus!(manifest);
    assert!(!manifest.tokens.is_empty());

    for token in &manifest.tokens {
        let value = decrypt_value(&token.token, &manifest.user_key)
            .unwrap_or_else(|error| panic!("{}: {error}", token.name));
        assert_eq!(value, token.expected, "{}", token.name);

        match &token.version {
            None => assert!(!is_encrypted_value(&token.token), "{}", token.name),
            Some(version) => {
                assert!(is_encrypted_value(&token.token), "{}", token.name);
                assert_eq!(token_version(&token.token), Some(version.as_str()));
            }
        }
    }
}

#[test]
fn every_bundle_imports_and_decrypts() {
    let manifest = corpus!(manifest);

    for bundle in &manifest.bundles {
        let (dir, keystore) = scratch(&format!("bundle-{}", bundle.name), manifest.iterations);

        let imported = keystore
            .import_store(&fixture(&bundle.path), Some(&bundle.import_as))
            .unwrap_or_else(|error| panic!("{}: {error}", bundle.name));
        assert_eq!(imported, bundle.import_as);

        let values = keystore
            .get_all(&manifest.user_key, &bundle.import_as)
            .expect("the imported store reads");

        for (key, expected) in &bundle.expected {
            assert_eq!(values.get(key), Some(expected), "{}/{key}", bundle.name);
        }

        // A hostile bundle must land entirely inside the target store.
        for name in &bundle.must_not_create {
            assert!(!dir.join(name).exists(), "{name} escaped the keystore");
            assert!(
                !dir.join(".keystore").join(name).exists(),
                "{name} escaped its store"
            );
        }
        for name in &bundle.must_create_inside_store {
            assert!(
                dir.join(".keystore").join(&bundle.import_as).join(name).exists(),
                "{name} should be inside the store"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn every_token_refusal_is_refused() {
    let manifest = corpus!(manifest);
    assert!(!manifest.refusals.tokens.is_empty());

    for refusal in &manifest.refusals.tokens {
        match decrypt_value(&refusal.token, &refusal.user_key) {
            Ok(value) => panic!("{} was not refused, returned {value:?}", refusal.name),
            Err(error) => assert_eq!(error.code.as_str(), refusal.code, "{}", refusal.name),
        }
    }
}

#[test]
fn every_bundle_refusal_is_refused() {
    let manifest = corpus!(manifest);
    let (dir, keystore) = scratch("bundle-refusals", manifest.iterations);

    for refusal in &manifest.refusals.bundles {
        match keystore.import_store(&fixture(&refusal.path), Some("target")) {
            Ok(_) => panic!("{} was not refused", refusal.name),
            Err(error) => assert_eq!(error.code.as_str(), refusal.code, "{}", refusal.name),
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_store_refusal_is_refused() {
    let manifest = corpus!(manifest);

    for refusal in &manifest.refusals.stores {
        match reader(&refusal.keystore_path).store_info(&refusal.store) {
            Ok(_) => panic!("{} was not refused", refusal.name),
            Err(error) => assert_eq!(error.code.as_str(), refusal.code, "{}", refusal.name),
        }
    }
}

/// The other direction: a store this crate wrote, holding the corpus's own
/// awkward values, read back. The JavaScript, Go, .NET and Python suites do the
/// same, which is what closes the loop.
#[test]
fn writes_a_store_that_reads_back() {
    let manifest = corpus!(manifest);

    let expected = &manifest
        .stores
        .iter()
        .find(|store| store.name == "basic")
        .expect("a 'basic' store in the corpus")
        .expected;

    let (dir, keystore) = scratch("cross-write", manifest.iterations);

    let input = dir.join("rust-written.env");
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    std::fs::write(&input, format!("master={}\nplaceholder=x", manifest.master_key))
        .expect("the input file");

    keystore
        .secure(&input, &manifest.user_key, Some("rust-written"))
        .expect("secure");

    for (key, value) in expected {
        keystore
            .set(key, value, &manifest.user_key, "rust-written")
            .unwrap_or_else(|error| panic!("set {key}: {error}"));
    }
    keystore
        .delete_key("placeholder", "rust-written")
        .expect("delete_key");

    let values = keystore
        .get_all(&manifest.user_key, "rust-written")
        .expect("get_all");
    assert_eq!(&values, expected);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A format 2.0 store read, migrated to 3.0, then read again.
#[test]
fn migrates_a_legacy_store() {
    let manifest = corpus!(manifest);

    let legacy = manifest
        .stores
        .iter()
        .find(|store| store.format == "2.0")
        .expect("a format 2.0 store in the corpus");

    let (dir, keystore) = scratch("migrate", manifest.iterations);

    // Copy the corpus store, so the fixtures are never written to.
    let source = fixture(&format!("{}/{}", legacy.keystore_path, legacy.name));
    let target = dir.join(".keystore").join(&legacy.name);
    std::fs::create_dir_all(&target).expect("the target directory");

    for entry in std::fs::read_dir(&source).expect("the corpus store").flatten() {
        std::fs::copy(entry.path(), target.join(entry.file_name())).expect("copying a fixture");
    }

    assert_eq!(keystore.store_info(&legacy.name).unwrap().version, "2.0");
    assert!(!keystore.store_info(&legacy.name).unwrap().current);

    let result = keystore
        .migrate(&legacy.name, &manifest.user_key)
        .expect("migrate");
    assert_eq!(result.from, "2.0");
    assert_eq!(result.to, "3.0");

    let values = keystore
        .get_all(&manifest.user_key, &legacy.name)
        .expect("the migrated store reads");
    assert_eq!(&values, &legacy.expected);
    assert!(keystore.store_info(&legacy.name).unwrap().current);

    let _ = std::fs::remove_dir_all(&dir);
}
