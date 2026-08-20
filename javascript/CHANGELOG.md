# Changelog

All notable changes to the JavaScript implementation are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

The **package version** and the **store format version** are separate numbers and
move at different speeds — see [SPEC.md §11](../SPEC.md#11-versioning).

## [3.0.0] - 2026-08-20

**Store format 3.0.** Faster, better bound, and portable to platforms 2.0 could
not reach. Every 2.0 store still opens, and every `skv1` token still decrypts.

This is also the release where JavaScript stopped being the only implementation:
Go, .NET, Python, PHP and Rust were written against
[SPEC.md](../SPEC.md), and a [shared conformance corpus](../conformance/) is what
holds all six to it.

### Changed — breaking

- **The store format is 3.0.** New stores use a 12-byte IV, bind every value to
  its key name, and derive value keys with HKDF. A 2.0 store is still read, and
  still *written* to — see Migration below.
- **The value token is `skv2`**, which records its own iteration count:
  `skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>`. `skv1` is still read,
  and never written. Its count is frozen at 100,000 because its layout has no
  field to record one in — which is the whole reason for the change.
- **The default iteration count is 600,000**, up from 100,000, following OWASP's
  2023 guidance for PBKDF2-HMAC-SHA256.
- **`safeFileName` now sanitises UTF-8 bytes, not UTF-16 characters.** A key named
  `ключ` used to produce `____-1de36a32.enc` here and `________-1de36a32.enc` in
  every other implementation. Reads were unaffected — the filename is recorded in
  `master.json` and the hash is the identity — but two implementations writing the
  same new key produced different files. Found by the conformance corpus;
  [SPEC.md §4.4](../SPEC.md#44-value-files) now fixes the definition in bytes.
- **Node 18 or later** (unchanged from 2.0.0, restated because 1.x was 14).

### Added

- **`migrate(storeName, userKey)`**, and `secure-keystore migrate`. Rewrites a
  whole store in the current format under fresh salts. Decrypts everything before
  writing anything, so a wrong user key leaves the store untouched; writes every
  value file before `master.json`, so an interruption leaves the store readable in
  its old format. Running it on a store already at 3.0 re-encrypts it, which is
  how a store's iteration count is raised.
- **`encryptValue(value, userKey, { iterations })`.** A token pays one PBKDF2
  stretch *per value*, unlike a store, so encrypting a whole column at 600,000
  rounds is hours. The count is recorded in the token, so a cheap token and an
  expensive one both read back.
- `tokenVersion(value)`, returning `'skv2'`, `'skv1'` or null.
- `getStoreInfo().current`, false when a store is still on 2.0 and would benefit
  from a migrate. `secure-keystore info` says so in words.
- `set()` returns `format`, so a caller can tell which format the record was
  written in.
- CLI `--iterations`, which applies to `secure`, `migrate` and `encrypt`.
- `ErrorCodes.UNSUPPORTED_FORMAT`, for a store or bundle newer than this build
  reads. A bundle from a future version was previously `BAD_BACKUP`.
- `STORE_FORMAT_LEGACY`, and `ALGORITHMS` now reports `ivBytes`, `passwordKdf`,
  `keyKdf` and `bindsKeyName`.

### Fixed

- **Reading a store no longer costs one PBKDF2 run per value.** Format 2.0 ran the
  full password KDF over the *master key* for every value — a password KDF applied
  to something that was never a password. 3.0 stretches the user key once and
  derives value keys with HKDF-SHA256, so opening a store costs **one** stretch
  however many keys it holds. The test suite runs 3.7× faster than 2.0's despite a
  six-fold higher iteration count.

### Security

- **A value is now bound to its key name**, as GCM additional authenticated data
  and as HKDF context. In 2.0 the tag covered the ciphertext and nothing else, so
  anyone with *write* access to a store could swap two `.enc` files and both would
  decrypt, under each other's names, silently. Documented as a known gap in 2.0.0;
  closed here, and asserted in `tests/format.test.js`.
- **The master key is bound to its own context**, so a store's encrypted master
  key cannot be lifted into another store.
- **The IV is 12 bytes**, which is NIST SP 800-38D's recommendation and — more
  practically — the only length .NET's `AesGcm` will accept at all. Format 2.0's
  16 bytes made every non-JavaScript platform reach for a workaround.
- **600,000 PBKDF2 rounds by default.** 2.0.0 made the count raisable; 3.0 raises
  it.

### Migrating from 2.0.0

Nothing is required. A 2.0 store opens, reads and writes exactly as before.

To move a store onto the stronger format:

```bash
secure-keystore export production ./backups/prod-before-migrate.skb   # first
secure-keystore migrate production "$USER_KEY"
```

```javascript
store.migrate('production', process.env.USER_KEY);
```

Until you do, that store keeps taking 2.0 writes — a store is never half one
format and half the other. `secure-keystore info` tells you which one it is on.

Existing `skv1` tokens keep decrypting indefinitely. Re-encrypting them is
optional:

```javascript
const { tokenVersion, decryptValue, encryptValue } = require('@tech-style/secure-keystore');

if (tokenVersion(row.token) === 'skv1') {
  row.token = encryptValue(decryptValue(row.token, userKey), userKey);
}
```

## [2.0.0] - 2026-08-20

Renamed, restructured, and made quiet. **Every store written by 1.x still opens**,
and every `skv1:` token still decrypts — the format did not change, the package
around it did.

### Changed — breaking

- **The package is now `@tech-style/secure-keystore`**, published under the Tech
  Style scope. It was `secure-keystore-js`.
- **The CLI is `secure-keystore`.** It was `secure`, which is a name no package
  should claim on a shared `PATH`.
- **`lib/` is now `src/`, and the CLI moved to `bin/cli.js`.** Anyone importing the
  package by name is unaffected; a deep import of
  `secure-keystore-js/lib/SecureKeystore` is not.
- **The root `index.js` is gone.** `main` points at `src/index.js`, and an
  `exports` map means the package now has exactly one public entry point.
- **The library no longer prints anything.** It used to `console.log` its way
  through every operation, which made it unusable from anything with opinions
  about its own logging. It now takes a `logger` option, defaulting to `null`; the
  CLI passes one. *If you relied on the library's output, pass
  `{ logger: console.log }`.*
- **Failures are `KeystoreError` with a `code`**, not bare `Error`s to be matched
  on by message. A wrong user key was node's own `Unsupported state or unable to
  authenticate data`; it is now `BAD_USER_KEY`, names the store, and keeps the
  original as `cause`.
- **Unknown constructor options are refused.** `{ keystoreDirectory: '/x' }` used
  to mean "write to the current directory and say nothing about it".
- **Node 18 or later**, up from 14.

### Added

- `iterations`, a constructor option for the PBKDF2 count — **and the count is now
  recorded** in `master.json` and in every value file, so a reader follows what a
  record says rather than its own default. This is what made 3.0's increase
  possible at all.
- `updated`, an ISO timestamp on every store, reported by `getStoreInfo` alongside
  the store's format version and iteration count.
- Named exports: `SecureKeystore`, `encryptValue`, `decryptValue`,
  `isEncryptedValue`, `KeystoreError`, `ErrorCodes`, `defaultOptions`, `Formats`,
  `VERSION`, `ALGORITHMS`. The default export is still the class.
- **TypeScript definitions**, hand-written, shipped in the package.
- `secure-keystore encrypt` and `decrypt` — the stateless token pair, from the
  command line.
- CLI `--json`, `--quiet`, `--keystore <dir>` and `--version`.
- **[SPEC.md](../SPEC.md)** — the format written down, which is what the other five
  implementations were later written against rather than reading this source.
- A real test suite, replacing one script that printed to the console and asserted
  very little.

### Fixed

- `deleteStore` refuses to delete anything that is not a store, rather than
  emptying whatever directory it was pointed at.
- `listStores` returns `[]` for a keystore directory that does not exist.
- A corrupt `index.json` is rebuilt rather than failing the write.
- `importStore` refuses a bundle whose format version is newer than this build
  understands.
- CLI `list` no longer asks for a user key it never verified.

### Security

- Documented that a value is **not** bound to its key name, with a test asserting
  the gap so that closing it could not quietly happen without the specification
  being updated. Closed in 3.0.0.
- Documented that 100,000 PBKDF2 iterations is below OWASP's guidance of 600,000,
  and made it raisable.
- Documented that the 16-byte GCM IV is a portability problem as well as a
  deviation from NIST guidance.

### Migrating from `secure-keystore-js` 1.x

```diff
- npm install secure-keystore-js
+ npm install @tech-style/secure-keystore

- const SecureKeystore = require('secure-keystore-js');
+ const { SecureKeystore } = require('@tech-style/secure-keystore');

- secure get api_key "$USER_KEY" production
+ secure-keystore get api_key "$USER_KEY" production
```

`const SecureKeystore = require('@tech-style/secure-keystore')` also still works —
the default export is unchanged. Your existing `.keystore` directory needs nothing
done to it.

## [1.1.0] - 2026-07-04

### Added

- `SecureKeystore.encryptValue` / `decryptValue`, stateless encryption of a single
  value with no store or master file, for applications that already have their own
  storage.

## [1.0.0]

First release, as `secure-keystore-js`.

### Added

- Two-layer encryption: a user key unlocks a per-store master key, and the master
  key unlocks each value under its own salt, with AES-256-GCM throughout.
- `secure`, `get`, `getAll`, `set`, `deleteKey`, `listStores`, `listKeys`,
  `getStoreInfo`, `exportStore`, `importStore` and `deleteStore`.
- Three input formats, chosen by extension: colon, dotenv and JSON.
- Export and import as a portable JSON bundle, replacing a shell-out to `tar` that
  did not work on Windows and passed a store name to a shell.
- Filenames built from a sanitised stem and a hash of the key, so a key named
  `../escape` cannot write outside its store and two keys that sanitise alike keep
  separate files.
- The `secure` command line.

[3.0.0]: https://github.com/eharain/secure-keystore/releases/tag/javascript%2Fv3.0.0
[2.0.0]: https://github.com/eharain/secure-keystore/releases/tag/javascript%2Fv2.0.0
[1.1.0]: https://github.com/eharain/secure-keystore/releases/tag/v1.1.0
[1.0.0]: https://github.com/eharain/secure-keystore/releases/tag/v1.0.0
