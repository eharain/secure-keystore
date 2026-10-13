# secure-keystore

**Encrypted secrets at rest, with no service to run.** AES-256-GCM over
PBKDF2-SHA256 and HKDF-SHA256, one documented format, six implementations, no
dependencies in any of them.

[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](SPEC.md)
[![implementations](https://img.shields.io/badge/implementations-6_languages-a3e635.svg)](#one-format-six-languages)

Your application needs an API key, a JWT secret and a database password. A
secrets service is a service to run, to authenticate against, and to be down when
you deploy. A `.env` file is plaintext on disk.

This is the third thing: **a directory of encrypted values, and one key that
opens it.**

```bash
printf 'master=MyMasterKey\napi_key=sk_live_abc123\njwt_secret=hunter2\n' > keys.env

secure-keystore secure keys.env "$USER_KEY" production   # encrypt everything
rm keys.env                                              # the plaintext is done

secure-keystore get api_key "$USER_KEY" production       # sk_live_abc123
```

```javascript
const { SecureKeystore } = require('@tech-style/secure-keystore');
const apiKey = new SecureKeystore().get('api_key', process.env.USER_KEY, 'production');
```

Deploying is copying a directory. There is nothing to start.

---

## How it works

```
user key ──PBKDF2-SHA256(600k rounds)──► user-derived key ──AES-256-GCM──► master key
master key ──HKDF-SHA256(salt, key name)──► value key ──AES-256-GCM──► value
```

| | |
|---|---|
| **Two layers** | A user key unlocks a per-store master key; the master key unlocks each value. |
| **The right KDF for each job** | The user key is a password, so it is stretched — expensively. The master key is not, so values derive from it with HKDF. Opening a store costs **one** stretch however many keys it holds. |
| **A salt per value** | Every value has its own random salt, its own derived key and its own IV. Two identical secrets look nothing alike on disk. |
| **Bound to its name** | The key name is authenticated data *and* HKDF context, so a value file moved to another key's name fails to decrypt. |
| **Authenticated** | AES-256-GCM. Tampering is detected, not decrypted around. |
| **Nothing to run** | A directory, and a key in an environment variable. |

The second layer is **not** a defence against a leaked user key — anyone with the
user key reaches everything, in one step. It is what lets every value carry its
own key material. The format is honest about this, and about
[everything else it does not protect](SPEC.md#8-what-this-format-does-not-protect).

---

## Also: encryption without a store

When the application already has somewhere to put the value — a database column,
a config row — and only wants it unreadable while it sits there:

```javascript
const { encryptValue, decryptValue } = require('@tech-style/secure-keystore');

const token = encryptValue('sk_live_abc123', process.env.USER_KEY);
// skv2:600000:8f3a…:02c1…:9db4…:7e2f…   — one self-describing string

decryptValue(token, process.env.USER_KEY);   // 'sk_live_abc123'
decryptValue('not encrypted', key);          // passed through unchanged
```

No master key, no directory, no deployment step. The token records the cost it
was made with, so encrypting a whole column cheaply and a single secret expensively
both work, and both read back.

---

## One format, six languages

The format is specified in [SPEC.md](SPEC.md), and every implementation was
written against **that document** rather than against another implementation. A
store written by any of them opens in all the others — which is not a claim but
[two tests](conformance/): a shared fixture corpus each one runs, and a matrix
where all six write and all six read every one of the results.

| Language | Registry | Package | Install |
|---|---|---|---|
| [**JavaScript**](javascript/) | npm | `@tech-style/secure-keystore` | `npm i @tech-style/secure-keystore` |
| [**Go**](go/) | Go modules | `github.com/eharain/secure-keystore/go/v3` | `go get github.com/eharain/secure-keystore/go/v3` |
| [**.NET**](dotnet/) | NuGet | `TechStyle.SecureKeystore` | `dotnet add package TechStyle.SecureKeystore` |
| [**Python**](python/) | PyPI | `secure-keystore` | `pip install secure-keystore` |
| [**PHP**](php/) | Packagist | `tech-style/secure-keystore` | `composer require tech-style/secure-keystore` |
| [**Rust**](rust/) | crates.io | `secure-keystore` | `cargo add secure-keystore` |

Across every one of them, three things are identical: the CLI verbs, the error
codes, and the `--json` output. Everything idiomatic — naming, error handling,
types — is deliberately not.

> **All six are verified against each other.** Each passes its own suite and the
> shared fixture corpus, and each writes a store, a token and a bundle that all
> six read back — 36 reader/writer combinations, 30 cross-language migrations,
> and every wrong key refused. Run it yourself with
> `node conformance/cross-test.mjs`; the detail is in
> [ROADMAP.md §3](ROADMAP.md#3-done--the-cross-implementation-matrix).

---

## The CLI

Every implementation ships one, with the same verbs.

```bash
secure-keystore secure <input-file> <user-key> [store-name]   # encrypt a file into a store
secure-keystore get <key> <user-key> [store-name]             # read one value
secure-keystore all <store-name> <user-key>                   # read them all
secure-keystore set <key> <value> <user-key> <store-name>     # add or rotate one
secure-keystore migrate <store-name> <user-key>               # bring a store to 3.0

secure-keystore stores                                        # what stores exist
secure-keystore list <store-name>                             # what keys are in one
secure-keystore info <store-name>                             # when, how many, what format

secure-keystore export <store-name> [path]                    # one portable .skb bundle
secure-keystore import <path> [store-name]

secure-keystore encrypt <value> <user-key>                    # a token, no store involved
secure-keystore decrypt <token> <user-key>

  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default 600000)
  --json               machine-readable output
  --quiet              results only, no progress
```

`get` writes the bare value to stdout, so `KEY=$(secure-keystore get api_key "$USER_KEY" prod)`
does what it looks like. Errors go to stderr prefixed with their code, and the
exit status is 1.

**A key name is not a secret.** `list`, `stores` and `info` read metadata and need
no user key; `get`, `all`, `set` and `migrate` decrypt, and do.

---

## Input formats

The format follows the extension. Every one needs a `master` entry.

```sh
# keys.txt — colon format, master on the first line. Only the first colon splits.
master:MyMasterKey
db_url:postgres://user:pass@host:5432/db

# keys.env — dotenv. Comments, quotes and `export` all handled.
master=MyMasterKey
export api_key=sk_live_abc123

# keys.json — a flat object. Non-string values are stringified.
{ "master": "MyMasterKey", "api_key": "sk_live_abc123", "port": 8080 }
```

---

## Where it fits

**Use it for** small and mid-sized applications, on-prem and air-gapped
deployments, CI/CD pipelines, containers, and anything that wants secrets
encrypted at rest without standing up a service to hold them.

**Do not use it for** enterprise-scale secret management, dynamic or short-lived
credentials, or anywhere a compliance regime requires FIPS validation or an audit
trail. HashiCorp Vault and the cloud KMSes exist and are better at that.

The full list of what this does not protect against — key names in the clear, one
root of trust, no audit log — is
[SPEC.md §8](SPEC.md#8-what-this-format-does-not-protect). It is worth reading
before you decide.

---

## Repository

```
secure-keystore/
├── SPEC.md          the format — what every implementation is written against
├── ROADMAP.md       what shipped, what is next, what is explicitly not planned
├── conformance/     fixtures every implementation reads, and the N x N matrix
├── javascript/      the reference implementation
├── go/  dotnet/  python/  php/  rust/
└── LICENSE
```

## Documentation

- **[SPEC.md](SPEC.md)** — the format, in enough detail to implement it
- **[ROADMAP.md](ROADMAP.md)** — format 3.0, the six ports, and what is next
- **[conformance/README.md](conformance/README.md)** — how cross-language
  compatibility is actually tested, and a bug it caught
- **[javascript/usage.md](javascript/usage.md)** — securing, deploying and reading
  at run time

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/) — see [LICENSE](LICENSE).
