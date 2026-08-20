# secure-keystore — Rust

**Encrypted secrets at rest, with no service to run.** RustCrypto underneath, and
nothing else.

[![crates.io](https://img.shields.io/badge/crates.io-secure--keystore-E33B26.svg)](https://crates.io/crates/secure-keystore)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-000000.svg)](https://www.rust-lang.org/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
cargo add secure-keystore
```

```rust
use secure_keystore::Keystore;

let store = Keystore::builder().build()?;
let api_key = store.get("api_key", &std::env::var("USER_KEY").unwrap(), Some("production"))?;
```

This is one of [six implementations](../README.md#one-format-six-languages) of the
[secure-keystore format](../SPEC.md). A store written here opens in the
JavaScript, Go, .NET, Python and PHP ones, and the other way round — which is not
a claim but [a test](tests/conformance.rs) against a corpus the JavaScript
implementation produced, and against
[`cross-test.mjs`](../conformance/cross-test.mjs), where all six write stores and
all six read every one of them.

---

## Two ways in

**A store** — a directory of encrypted values that one user key opens.

**A token** — one string in, one string out, nothing on disk.

```rust
use secure_keystore::{encrypt_value, decrypt_value};

let token = encrypt_value("sk_live_abc123", "user-key", None)?;
let back = decrypt_value(&token, "user-key")?;
```

---

## API

### `Keystore::builder()`

Binds one keystore directory and one set of options, validated once in `build()`
rather than on every call. The instance holds no secret: the user key is passed to
each call that needs one and is never retained.

```rust
use secure_keystore::Keystore;

let store = Keystore::builder()
    .keystore_dir("/var/lib/app/keys")
    .iterations(600_000)
    .logger(|message| println!("{message}"))
    .build()?;
```

| Method | Default | |
|---|---|---|
| `keystore_dir` | `./.keystore` | Where stores live. |
| `iterations` | `600_000` | PBKDF2 rounds for the *user key*, on new and migrated stores. Recorded in the store. Does not apply to value keys, which use HKDF. |
| `logger` | none | Called with one line of progress. **Without one the crate prints nothing** — the default, and what a server wants. |
| `create_dir` | `true` | Create the keystore directory if absent. |

### Store operations

```rust
fn secure(&self, input_file: &Path, user_key: &str, store_name: Option<&str>) -> Result<SecureResult>
fn get(&self, key: &str, user_key: &str, store_name: Option<&str>) -> Result<String>
fn get_all(&self, user_key: &str, store_name: &str) -> Result<BTreeMap<String, String>>
fn set(&self, key: &str, value: &str, user_key: &str, store_name: &str) -> Result<SetResult>
fn migrate(&self, store_name: &str, user_key: &str) -> Result<MigrateResult>
fn delete_key(&self, key: &str, store_name: &str) -> Result<()>
fn delete_store(&self, store_name: &str) -> Result<()>
```

`get_all` costs **one** PBKDF2 derivation however many keys the store holds — see
[SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).

### Metadata — no user key needed

```rust
fn list_stores(&self) -> Result<Vec<String>>
fn list_keys(&self, store_name: &str) -> Result<Vec<String>>
fn store_info(&self, store_name: &str) -> Result<StoreInfo>
```

Key names live in metadata in the clear, so **a key name must not itself be a
secret**.

### Bundles and tokens

```rust
fn export_store(&self, store_name: &str, backup_path: Option<&Path>) -> Result<PathBuf>
fn import_store(&self, backup_path: &Path, store_name: Option<&str>) -> Result<String>

pub fn encrypt_value(plaintext: &str, user_key: &str, iterations: Option<u32>) -> Result<String>
pub fn decrypt_value(token: &str, user_key: &str) -> Result<String>
pub fn is_encrypted_value(value: &str) -> bool
pub fn token_version(value: &str) -> Option<&str>
```

`iterations` lowers the cost for bulk work — a token pays one stretch **per
value**, unlike a store. The count is recorded in the token, so decryption follows
whatever was chosen.

---

## Errors

Every fallible call returns `Result<T, Error>`, and every `Error` carries a stable
`Code`:

```rust
use secure_keystore::Code;

match store.get("api_key", &user_key, Some("production")) {
    Ok(value) => { /* ... */ }
    Err(error) if error.code == Code::BadUserKey => { /* wrong password */ }
    Err(error) => return Err(error),
}
```

`Code::as_str()` gives the wire string — `"BAD_USER_KEY"` — which is identical in
all six implementations. See [SPEC.md §10](../SPEC.md#10-errors).

Nothing in this crate panics on bad input, and `#![forbid(unsafe_code)]` is set at
the crate root.

---

## Notes specific to Rust

**`Aes256Gcm` is enough — now.** Format 3.0 uses a 12-byte nonce, which is what
`Aes256Gcm` is typed to. Reading a format 2.0 store needs `AesGcm<Aes256, U16>`
spelled out, and that is the only place this crate uses it. See
[ROADMAP.md §1.1](../ROADMAP.md#11-a-12-byte-iv) for why the format changed.

**`serde_json` is built with `preserve_order`**, so `entries` keeps its order and
a rewrite of `master.json` keeps the document's own key order.

**Unknown fields survive a rewrite.** The metadata is carried as a
`Map<String, Value>` rather than a struct, because an older reader that silently
downgrades a store written by a newer implementation is worse than one that
refuses it.

**No date dependency.** The one timestamp this crate writes uses Howard Hinnant's
`civil_from_days`, twelve lines, rather than pulling in `chrono` for nothing else.

---

## The CLI

```bash
cargo install secure-keystore
secure-keystore get api_key "$USER_KEY" production
```

Same verbs, flags, error codes and `--json` output as every other
implementation — see the [root README](../README.md#the-cli).

---

## Development

```bash
cargo test                  # includes the shared corpus
cargo clippy -- -D warnings
cargo build --release
```

```
rust/
├── src/
│   ├── lib.rs            the public surface
│   ├── format.rs         everything the format fixes
│   ├── error.rs          Error, Code, Result
│   ├── crypto.rs         PBKDF2, HKDF, AES-GCM — the only place a cipher is built
│   ├── token.rs          the stateless skv2 token
│   ├── input.rs          the three input formats, testable without a file
│   ├── bundle.rs         the .skb bundle
│   ├── keystore.rs       the store itself
│   └── bin/secure-keystore.rs
└── tests/conformance.rs
```

`Cargo.lock` is not committed: this is a library, and the lock file of a library
binds nobody — the CI matrix wants to resolve fresh.

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../conformance/](../conformance/)** — how cross-language compatibility is tested
- **[CHANGELOG.md](CHANGELOG.md)**

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
