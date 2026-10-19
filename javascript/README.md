# @tech-style/secure-keystore

**Encrypted secrets at rest for Node.js, with no service to run.** AES-256-GCM
over PBKDF2-SHA256 and HKDF-SHA256. No dependencies — `node:crypto` is all it
needs.

[![npm](https://img.shields.io/npm/v/@tech-style/secure-keystore.svg)](https://www.npmjs.com/package/@tech-style/secure-keystore)
[![node](https://img.shields.io/badge/node-18%2B-339933.svg)](https://nodejs.org/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
npm install @tech-style/secure-keystore
```

```javascript
const { SecureKeystore } = require('@tech-style/secure-keystore');

const store = new SecureKeystore();
const userKey = process.env.USER_KEY;          // never hardcode this

store.secure('./keys.env', userKey, 'production');   // encrypt a file into a store
const apiKey = store.get('api_key', userKey, 'production');
```

This is the reference implementation of the
[secure-keystore format](../SPEC.md), and one of
[six](../README.md#one-format-six-languages). Deploying is copying a directory;
there is nothing to start.

## Video

[![Secure Keystore: encrypted secrets at rest, with no service to run](https://raw.githubusercontent.com/eharain/secure-keystore/main/docs/media/video-thumbnail.jpg)](https://www.youtube.com/watch?v=ai-yHqZS_G4)

A 0:59 introduction on YouTube, with English captions.

---

## Two ways in

They are for different things, and it is worth being clear which you want.

**A store** — a directory of encrypted values that one user key opens. The store
owns a master key, one salt per value, and a catalogue. Deploy the directory,
read secrets out of it at run time.

**A token** — one string in, one string out, nothing on disk. You already have
somewhere to put it: a database column, a config row. You only want it
unreadable while it sits there.

```javascript
const { SecureKeystore, encryptValue, decryptValue } = require('@tech-style/secure-keystore');
```

---

## Quick start

**1. Write a keys file.** The format follows the extension; each needs a
`master` entry.

```bash
printf 'master=MyMasterKey\napi_key=sk_live_abc123\njwt_secret=hunter2\n' > keys.env
```

**2. Secure it, then delete the plaintext.**

```bash
npx secure-keystore secure keys.env "$USER_KEY" production
rm keys.env
```

**3. Read it back, from the shell or from code.**

```bash
secure-keystore get api_key "$USER_KEY" production
```

```javascript
const store = new SecureKeystore();
const apiKey = store.get('api_key', process.env.USER_KEY, 'production');
```

---

## API

### `new SecureKeystore(options?)`

One instance binds one keystore directory and one set of options, **validated
here rather than on first use** — so a typo throws where it was written. The
instance holds no secret: the user key is passed to each call that needs one and
is never retained.

| Option | Default | |
|---|---|---|
| `keystoreDir` | `./.keystore` | Where stores live. |
| `iterations` | `600000` | PBKDF2 rounds the *user key* is stretched with, on new and migrated stores. Recorded in the store. Does **not** apply to value keys, which use HKDF — see below. |
| `logger` | `null` | Called with one line of progress. **Null means the library prints nothing** — which is the default, and what a server wants. |
| `createDir` | `true` | Create the keystore directory if it is absent. |

An unknown option is an error, not a silent no-op. `{ keystoreDirectory: … }`
used to mean "write to the current directory and say nothing about it".

### `secure(inputFile, userKey, storeName?)`

Encrypts a key-value file into a store. The store name defaults to the input
file's base name. Re-securing replaces the store, removing the old `.enc` files
first so a dropped key does not linger as an orphan.

Returns `{ storeName, storeDir, totalKeys, keys }`.

### `get(key, userKey, storeName?)`

Decrypts one value. With no store name, every store is searched — a convenience
for one store and a trap for several, where two may hold the same key name and
the first match wins.

### `getAll(userKey, storeName)`

Every value in the store, as `{ key: value }`.

### `set(key, value, userKey, storeName)`

Adds a key or replaces an existing value. The replacement gets a fresh salt and
IV, so an observer who kept the old file learns nothing by comparing.

Returns `{ key, storeName, added, format }`. On a store still in format 2.0 this
writes a 2.0 record, so the store stays internally consistent — run `migrate` to
move the whole store across.

### `migrate(storeName, userKey)`

Rewrites a whole store in the current format, under fresh salts and the
instance’s iteration count. Use it to bring a format 2.0 store to 3.0, or to
raise the iteration count of a store already on 3.0.

Every value is decrypted before anything is written, so a wrong user key leaves
the store untouched; every new value file is written before `master.json`, so an
interruption leaves the store readable in its old format. Export first anyway.

Returns `{ storeName, from, to, keys, iterations }`.

### `deleteKey(key, storeName)` / `deleteStore(storeName)`

Removes one key and its file, or the whole store and its index entry.
`deleteStore` refuses a directory that is not a store, so it cannot be pointed
at something else by mistake.

### `listStores()` / `listKeys(storeName)` / `getStoreInfo(storeName)`

No user key, and none needed: names live in metadata in the clear. That is the
trade that makes a store inspectable without a password, and it means **a key
name must not itself be a secret.**

`getStoreInfo` returns `{ name, path, version, current, created, updated,
iterations, totalKeys, keys, sourceFile }`. `current` is false when the store is
still on format 2.0.

### `exportStore(storeName, backupPath?)` / `importStore(backupPath, storeName?)`

A whole store as one JSON bundle, `.skb` by default. Pure JavaScript — no `tar`,
no shell — so it behaves the same on Windows as anywhere else. The contents are
already encrypted, so a bundle is safe to put through a CI artifact store.

Import reduces every name in the bundle to its base name before writing, because
a bundle is an untrusted file and `"../../.ssh/authorized_keys"` is one somebody
can write by hand.

---

## Encryption without a store

```javascript
const { encryptValue, decryptValue, isEncryptedValue } = require('@tech-style/secure-keystore');

const token = encryptValue('sk_live_abc123', process.env.USER_KEY);
// 'skv1:8f3a…:02c1…:9db4…:7e2f…'   — safe to put in any column

decryptValue(token, process.env.USER_KEY);     // 'sk_live_abc123'
```

Fresh salt and IV per call, so the same secret encrypts to different bytes every
time and a column never reveals which rows share a value.

Two behaviours make this usable on a table you are part way through encrypting:

- `encryptValue` returns `null`, `undefined` and `''` unchanged, so it maps over
  a record without you sorting the empty fields out first.
- `decryptValue` passes anything that is not a token straight through, and reads
  both `skv2` and the older `skv1`.

A value that **is** a token but is malformed, altered, or written under a
different user key **throws** — it is never passed through, which would hand you
ciphertext you believed was plaintext.

### The cost is yours to choose

```javascript
encryptValue(value, userKey, { iterations: 50000 });   // for a whole column
```

A store pays one PBKDF2 stretch however many keys it holds. A token pays one
**per value**, so encrypting ten thousand rows at the 600,000 default is hours.
The count is recorded in the token, so a cheap token and an expensive one both
read back — which is exactly what `skv1` could not do, and why `skv2` exists.

`tokenVersion(value)` returns `skv2`, `skv1` or null, for a caller deciding
what to re-encrypt.

Both are also instance methods (`store.encryptValue(…)`).

---

## Errors

Every failure is a `KeystoreError` with a stable `code`. The message may be
reworded between releases; the code will not be.

```javascript
const { KeystoreError, ErrorCodes } = require('@tech-style/secure-keystore');

try {
  store.get('api_key', userKey, 'production');
} catch (error) {
  if (error.code === ErrorCodes.BAD_USER_KEY) { /* wrong password */ }
  if (error.code === ErrorCodes.STORE_NOT_FOUND) { /* not deployed yet */ }
}
```

| Code | |
|---|---|
| `INVALID_OPTIONS` | The constructor options do not make sense. |
| `INVALID_ARGUMENT` | A required argument was missing or empty. |
| `STORE_NOT_FOUND` | No such store under this keystore directory. |
| `STORE_CORRUPT` | The directory exists but is not a store, or its metadata is unreadable. |
| `KEY_NOT_FOUND` | No such key — in the named store, or in any of them. |
| `BAD_USER_KEY` | Decryption failed: wrong key, or the bytes were altered. |
| `BAD_TOKEN` | A value token is not in the form this library writes. |
| `BAD_INPUT` | The input file is not readable as the format its extension claims. |
| `BAD_BACKUP` | The bundle is missing, unreadable, or not a keystore bundle. |
| `UNSUPPORTED_FORMAT` | The store or bundle is newer than this build reads. |

A wrong user key used to surface as node's own `Unsupported state or unable to
authenticate data`. It now says which store, and keeps the original as `cause`.

---

## The CLI

```bash
npm install -g @tech-style/secure-keystore
```

```bash
secure-keystore secure <input-file> <user-key> [store-name]
secure-keystore get <key> <user-key> [store-name]
secure-keystore all <store-name> <user-key>
secure-keystore set <key> <value> <user-key> <store-name>

secure-keystore stores
secure-keystore list <store-name>
secure-keystore info <store-name>
secure-keystore delete <key> <store-name>
secure-keystore delete-store <store-name>

secure-keystore export <store-name> [backup-path]
secure-keystore import <backup-path> [store-name]

secure-keystore encrypt <value> <user-key>
secure-keystore decrypt <token> <user-key>

  --keystore <dir>   where stores live (default ./.keystore)
  --json             machine-readable output
  --quiet            results only, no progress
```

`get` writes the bare value, so `KEY=$(secure-keystore get api_key "$USER_KEY" prod)`
works. Errors go to stderr prefixed with their code, and the exit status is 1.

---

## TypeScript

Types ship with the package — no `@types` install.

```typescript
import { SecureKeystore, encryptValue, ErrorCodes, type StoreInfo } from '@tech-style/secure-keystore';
```

---

## Security model

| Threat | What stops it |
|---|---|
| Someone walks off with the `.keystore` directory | Every value is AES-256-GCM encrypted; useless without the user key. |
| Someone edits a ciphertext | The GCM tag fails and decryption throws. |
| Offline brute force of the user key | 600,000 PBKDF2-SHA256 rounds per guess, raisable per store. |
| Working out which secrets are equal | Random salt and IV per value; identical secrets differ on disk. |
| Someone swaps two `.enc` files | Every value is bound to its key name, so a moved file fails to decrypt. |

**And what does not:**

- **The user key is the whole root of trust.** If it leaks, every value it opens
  is readable. The second layer does not change that.
- **Key names are in the clear.** Anyone with read access learns a store has an
  `aws_secret_access_key`, though not what it is.
- No audit log, no protection against a compromised host, no side-channel
  hardening, no FIPS validation. A decrypted value is plaintext in process memory
  for as long as you hold it.

> **Closed in 3.0.** Format 2.0 did not bind a value to its key name, so anyone
> with write access could swap two `.enc` files and both would decrypt under the
> wrong names. A store still on 2.0 still has that gap — `migrate` it.

The full statement is [SPEC.md §8](../SPEC.md#8-what-this-format-does-not-protect).

---

## Practices worth adopting

```bash
export USER_KEY=$(openssl rand -base64 32)          # long, random, from the environment
```

```gitignore
.keystore/
keys.txt
keys.env
keys.json
*.skb
```

- One store per environment: `development`, `staging`, `production`.
- Delete the plaintext keys file the moment the store exists.
- End a deploy by reading a key back. A store that copied cleanly but was
  written under a different user key fails there, and not at three in the
  morning.
- Back up before rotating: `secure-keystore export production ./backups/prod-$(date +%Y%m%d).skb`.

---

## Development

```bash
npm test                        # node --test, 84 tests including the shared corpus
node examples/basic-usage.js
node examples/deployment.js
```

```
src/
├── index.js        the public surface
├── constants.js    everything the format fixes
├── options.js      defaults, validation
├── errors.js       KeystoreError and its codes
├── crypto.js       PBKDF2, HKDF, AES-GCM — the only place a cipher is built
├── value.js        the stateless skv2 token, and skv1 for reading
├── parse.js        the three input formats, testable without a file
├── backup.js       the .skb bundle
└── store.js        the store itself
```

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../ROADMAP.md](../ROADMAP.md)** — format 3.0 and the other five languages
- **[usage.md](usage.md)** — securing, deploying and reading at run time
- **[CHANGELOG.md](CHANGELOG.md)** — what changed in 2.0.0, and what breaks

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
