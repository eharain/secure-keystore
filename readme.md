# SecureKeystore

Secure key-value store with two-layer encryption for Node.js.

Secrets live encrypted on disk and are only decrypted, in memory, when you ask
for them. A single **user key** unlocks a per-store **master key**, which in
turn unlocks each individual value.

## Features

- 🔐 **Two-layer encryption** — user key unlocks the master key, master key unlocks each value
- 📁 **Per-key encryption** — every value is encrypted independently with its own random salt and IV
- 🚀 **Zero dependencies** — pure Node.js `crypto`
- 📦 **Multiple stores** — production, staging, development, …
- 🔄 **Import / export** — portable, cross-platform JSON backup bundles
- 🛠️ **CLI tool** — simple command-line interface
- 🔒 **AES-256-GCM** — authenticated encryption (tampering is detected)

## Installation

```bash
npm install secure-keystore-js
```

Installing globally (`npm install -g secure-keystore-js`) exposes the `secure`
command. Without a global install you can run the CLI directly with
`node node_modules/secure-keystore-js/lib/cli.js …` (or `node lib/cli.js …` from a
clone of this repo).

## Quick start

**1. Create a keys file.** Three formats are supported (chosen by extension);
each must define a `master` key. The colon format requires `master` on the first line:

```bash
# .txt — colon format (master must be the first line)
printf 'master:MyMasterKey123\napi_key:sk_live_abc123\njwt_secret:secret123\n' > keys.txt

# .env — dotenv format (comments, quotes, and `export` are supported)
printf 'master=MyMasterKey123\napi_key=sk_live_abc123\njwt_secret="secret123"\n' > keys.env

# .json — a flat object of string values
printf '{ "master": "MyMasterKey123", "api_key": "sk_live_abc123" }\n' > keys.json
```

See [examples/](examples/) for `keys.txt`, `keys.env`, and `keys.json` samples.

**2. Secure the file** (encrypts everything into a store named `production`):

```bash
secure secure keys.txt myUserKey123 production
```

**3. Read a key back:**

```bash
secure get api_key myUserKey123 production
```

> Delete the plaintext `keys.txt` once the store is created — it is no longer needed.

## CLI

```bash
# Encrypt a key-value file into a store (store name defaults to the file name)
secure secure <input-file> <user-key> [store-name]

# Read one value
secure get <key> <user-key> [store-name]

# Read every value in a store
secure all <store-name> <user-key>

# Add or update a key
secure set <key> <value> <user-key> <store-name>

# List the key names in a store (no decryption needed)
secure list <store-name> <user-key>

# Delete a single key / an entire store
secure delete <key> <store-name>
secure delete-store <store-name>

# Inspect stores
secure stores
secure info <store-name>

# Backup / restore (portable .skb bundle)
secure export <store-name> [backup-path]
secure import <backup-path> [store-name]

secure --help
```

> `secure list` only reads key **names** from metadata, so the `<user-key>`
> argument is currently accepted but not verified. `get`, `all`, and `set` are
> the operations that actually require a correct user key.

## API

```javascript
const SecureKeystore = require('secure-keystore-js');

const store = new SecureKeystore();        // keystore lives in ./.keystore
const userKey = process.env.USER_KEY;      // never hardcode this

store.secure('./keys.txt', userKey, 'production');
const apiKey = store.get('api_key', userKey, 'production');
store.set('new_key', 'new_value', userKey, 'production');
const all = store.getAll(userKey, 'production');
```

### `new SecureKeystore(options)`
- `options.keystoreDir` — directory the keystore is stored in (default: `./.keystore`).

### Stateless value encryption (no disk store)

When your app already has its own storage (a database, a config store) and you
only want a value encrypted at rest, use the static helpers — there is no store
or master file, just a user key:

```javascript
const SecureKeystore = require('secure-keystore-js');

const userKey = process.env.USER_KEY;                 // never hardcode
const token = SecureKeystore.encryptValue('sk_live_abc123', userKey);
// -> "skv1:<salt>:<iv>:<authTag>:<ciphertext>"  (safe to store anywhere)

const secret = SecureKeystore.decryptValue(token, userKey);   // 'sk_live_abc123'
```

- **`SecureKeystore.encryptValue(plaintext, userKey)`** → encrypted token string.
  Each call uses a fresh random salt + IV (AES-256-GCM, PBKDF2-SHA256 100k). A
  `null`/`undefined`/`''` input is returned unchanged.
- **`SecureKeystore.decryptValue(token, userKey)`** → plaintext. A value that is
  not an `skv1:` token is returned unchanged (so you can decrypt-if-encrypted);
  a tampered token or wrong `userKey` throws.

Both are also available as instance methods (`store.encryptValue(...)`).

### `secure(inputFile, userKey, storeName?)`
Encrypts a key-value file. The input format is chosen by file extension:

- **`.json`** — a flat JSON object; the `master` property is the master key.
- **`.env`** — dotenv-style `KEY=value` lines (supports `#` comments, single/double
  quotes, and an optional `export ` prefix); the `master=` line is the master key.
- **anything else (`.txt`)** — colon format: the first line must be
  `master:<your-master-key>`, followed by `key:value` lines.

If `storeName` is omitted it defaults to the input file's base name. Re-securing
an existing store replaces its contents. Returns `{ storeName, storeDir, totalKeys, keys }`.

### `get(key, userKey, storeName?)`
Decrypts and returns a single value. If `storeName` is omitted, every store is
searched for the key.

### `getAll(userKey, storeName)`
Returns an object of all decrypted `{ key: value }` pairs in a store.

### `set(key, value, userKey, storeName)`
Adds a new key or updates an existing one.

### `deleteKey(key, storeName)`
Removes a single key (and its encrypted file) from a store.

### `listKeys(storeName)` / `listStores()`
Returns the key names in a store / the names of all stores. No decryption.

### `getStoreInfo(storeName)`
Returns `{ name, path, created, totalKeys, keys, sourceFile }`.

### `exportStore(storeName, backupPath?)` / `importStore(backupPath, storeName?)`
Export writes a self-contained JSON bundle (default extension `.skb`). Import
restores it. Pure JavaScript — no external `tar` binary — so it behaves
identically on Windows, macOS, and Linux.

### `deleteStore(storeName)`
Permanently removes a store and its index entry.

## How encryption works

1. A random 32-byte salt is generated for the store. `PBKDF2(userKey, salt, 100k, SHA-256)`
   derives a key that encrypts the **master key** with AES-256-GCM.
2. Each value gets its **own random 32-byte salt**. `PBKDF2(masterKey, valueSalt, 100k, SHA-256)`
   derives a per-value key that encrypts that value with AES-256-GCM.
3. Each encryption uses a fresh random IV, so identical plaintexts produce
   different ciphertexts.

Files written per store:

```
.keystore/
  index.json              # catalog of stores (names + key names, no secrets)
  <store>/
    master.json           # store metadata + the encrypted master key
    <key>-<hash>.enc      # one authenticated-encrypted file per value
```

## Security model — what it does and does not protect

| Threat | Mitigation |
| --- | --- |
| Stolen `.keystore` files | Values are AES-256-GCM encrypted; useless without the user key |
| Tampering with ciphertext | GCM auth tag fails decryption |
| Offline brute force of the user key | 100,000 PBKDF2 iterations slow each guess |
| Pattern analysis | Random salt + random IV per value; identical values differ on disk |

**Honest limitations — please read:**

- **The user key is the single root of trust.** If it leaks, an attacker can
  derive the master key and decrypt *everything* in the store. There is no
  meaningful "only one layer compromised" property.
- **No audit logging, no key rotation, no dynamic/short-lived secrets.**
- **No protection against a compromised host.** While your app holds a decrypted
  value, it is plaintext in process memory.
- **Not side-channel hardened** and **not FIPS-validated.** Don't use it where
  those properties are required.

### When to use it
Small/medium apps, offline or on-prem deployments, CI/CD pipelines, and
containerized apps that want encrypted-at-rest secrets without standing up a
secrets service.

### When *not* to use it
Enterprise-scale secret management, dynamic secrets, or strict compliance
(HIPAA/SOC2/FIPS). Use a dedicated system such as HashiCorp Vault or a cloud KMS.

## Best practices

- Use a long, random user key and supply it via an environment variable:
  `export USER_KEY=$(openssl rand -base64 32)`.
- Add the keystore and any plaintext key files to `.gitignore`:
  ```
  .keystore/
  *.enc
  keys.txt
  ```
- Use a separate store per environment (`development`, `staging`, `production`).
- Back up regularly: `secure export production ./backups/prod-$(date +%Y%m%d).skb`.

## License

MIT © ejaz arain — [tech-style.co](https://www.tech-style.co/)
