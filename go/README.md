# secure-keystore — Go

**Encrypted secrets at rest, with no service to run.** No dependencies at all —
`crypto/aes`, `crypto/pbkdf2` and `crypto/hkdf` are the whole of it.

[![Go reference](https://pkg.go.dev/badge/github.com/eharain/secure-keystore/go/v3.svg)](https://pkg.go.dev/github.com/eharain/secure-keystore/go/v3)
[![Go version](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](https://go.dev/dl/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
go get github.com/eharain/secure-keystore/go/v3
```

```go
import ks "github.com/eharain/secure-keystore/go/v3"

store, err := ks.New()
apiKey, err := store.Get("api_key", os.Getenv("USER_KEY"), "production")
```

The command line installs on its own:

```bash
go install github.com/eharain/secure-keystore/go/v3/cmd/secure-keystore@latest
secure-keystore get api_key "$USER_KEY" production
```

This is one of [six implementations](../README.md#one-format-six-languages) of the
[secure-keystore format](../SPEC.md). A store written here opens in the
JavaScript, .NET, Python, PHP and Rust ones, and the other way round — which is
not a claim but [a test](conformance_test.go) against a corpus the JavaScript
implementation produced.

**Go 1.24 or later**, because `crypto/pbkdf2` and `crypto/hkdf` landed there. No
third-party dependency, and no `go.sum`.

## Video

[![Secure Keystore: encrypted secrets at rest, with no service to run](https://raw.githubusercontent.com/eharain/secure-keystore/main/docs/media/video-thumbnail.jpg)](https://www.youtube.com/watch?v=ai-yHqZS_G4)

A 0:59 introduction on YouTube, with English captions.

---

## Two ways in

**A store** — a directory of encrypted values that one user key opens. Deploy the
directory, read secrets out of it at run time.

**A token** — one string in, one string out, nothing on disk. You already have
somewhere to put it: a database column, a config row.

```go
token, err := ks.EncryptValue("sk_live_abc123", userKey)
back, err := ks.DecryptValue(token, userKey)
```

---

## API

### `New(options ...Options) (*Keystore, error)`

Binds one keystore directory and one set of options, validated once here rather
than on every call. The instance holds no secret: the user key is passed to each
call that needs one and is never retained, so one built at start-up is safe for
the life of the process.

```go
options := ks.DefaultOptions()
options.KeystoreDir = "/var/lib/app/keys"
options.Iterations = 600_000
options.Logger = func(message string) { log.Println(message) }

store, err := ks.New(options)
```

| Field | Default | |
|---|---|---|
| `KeystoreDir` | `./.keystore` | Where stores live. |
| `Iterations` | `600000` | PBKDF2 rounds for the *user key*, on new and migrated stores. Recorded in the store. Does not apply to value keys, which use HKDF. |
| `Logger` | `nil` | Called with one line of progress. **Nil means the package prints nothing** — the default, and what a server wants. |
| `CreateDir` | `true` | Create the keystore directory if absent. |

### Store operations

```go
func (k *Keystore) Secure(inputFile, userKey, storeName string) (*SecureResult, error)
func (k *Keystore) Get(key, userKey, storeName string) (string, error)
func (k *Keystore) GetAll(userKey, storeName string) (map[string]string, error)
func (k *Keystore) Set(key, value, userKey, storeName string) (*SetResult, error)
func (k *Keystore) Migrate(storeName, userKey string) (*MigrateResult, error)
func (k *Keystore) DeleteKey(key, storeName string) error
func (k *Keystore) DeleteStore(storeName string) error
```

An empty `storeName` on `Secure` defaults to the input file's base name; on `Get`
it searches every store, which is a convenience for one store and a trap for
several.

`GetAll` costs **one** PBKDF2 derivation however many keys the store holds — see
[SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).

### Metadata — no user key needed

```go
func (k *Keystore) ListStores() ([]string, error)
func (k *Keystore) ListKeys(storeName string) ([]string, error)
func (k *Keystore) StoreInfo(storeName string) (*StoreInfo, error)
```

Key names live in metadata in the clear. That is the trade that makes a store
inspectable without a password, and it means **a key name must not itself be a
secret**.

### Bundles

```go
func (k *Keystore) ExportStore(storeName, backupPath string) (string, error)
func (k *Keystore) ImportStore(backupPath, storeName string) (string, error)
```

One portable `.skb` file, already encrypted. Import reduces every name in the
bundle to its base name — treating both separators as separators whatever the
host — because a bundle is an untrusted file that arrived over a wire.

### Tokens

```go
func EncryptValue(plaintext, userKey string, options ...TokenOptions) (string, error)
func DecryptValue(token, userKey string) (string, error)
func IsEncryptedValue(s string) bool
func TokenVersion(s string) string
```

`TokenOptions{Iterations: n}` lowers the cost for bulk work — a token pays one
stretch **per value**, unlike a store. The count is recorded in the token, so
decryption follows whatever was chosen.

---

## Errors

Every failure is a `*ks.Error` with a `Code`. Both the idiomatic Go check and the
cross-language code work:

```go
if errors.Is(err, ks.ErrBadUserKey) { /* wrong password */ }
if ks.CodeOf(err) == ks.CodeBadUserKey { /* the same thing */ }
```

| Sentinel | Code |
|---|---|
| `ErrInvalidOptions` | `INVALID_OPTIONS` |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` |
| `ErrStoreNotFound` | `STORE_NOT_FOUND` |
| `ErrStoreCorrupt` | `STORE_CORRUPT` |
| `ErrKeyNotFound` | `KEY_NOT_FOUND` |
| `ErrBadUserKey` | `BAD_USER_KEY` |
| `ErrBadToken` | `BAD_TOKEN` |
| `ErrBadInput` | `BAD_INPUT` |
| `ErrBadBackup` | `BAD_BACKUP` |
| `ErrUnsupportedFormat` | `UNSUPPORTED_FORMAT` |

The codes are identical in all six implementations; a script that greps for
`BAD_USER_KEY` keeps working when the service is rewritten in another language.

---

## Notes specific to Go

**`cipher.NewGCM` is enough — now.** Format 3.0 uses a 12-byte IV, which is what
`NewGCM` produces without argument. Reading a format 2.0 store still needs
`cipher.NewGCMWithNonceSize(block, 16)`, and that is the only place this package
reaches for it. See [ROADMAP.md §1.1](../ROADMAP.md#11-a-12-byte-iv) for why the
format changed.

**Unknown fields survive a rewrite.** `master.json` round-trips through a custom
marshaller that keeps anything this build does not recognise, because an older
reader that silently downgrades a store written by a newer implementation is
worse than one that refuses it.

**Concurrency.** Safe for concurrent reads. Concurrent writes to the *same* store
are not serialised by this package.

---

## The CLI

```bash
go install github.com/eharain/secure-keystore/go/v3/cmd/secure-keystore@latest
```

```bash
secure-keystore secure <input-file> <user-key> [store-name]
secure-keystore get <key> <user-key> [store-name]
secure-keystore all <store-name> <user-key>
secure-keystore set <key> <value> <user-key> <store-name>
secure-keystore migrate <store-name> <user-key>

secure-keystore stores
secure-keystore list <store-name>
secure-keystore info <store-name>
secure-keystore delete <key> <store-name>
secure-keystore delete-store <store-name>

secure-keystore export <store-name> [backup-path]
secure-keystore import <backup-path> [store-name]

secure-keystore encrypt <value> <user-key>
secure-keystore decrypt <token> <user-key>

  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default 600000)
  --json               machine-readable output
  --quiet              results only, no progress
```

A single static binary is the strongest form of this — nothing to install on the
target machine but the file.

---

## Development

```bash
go test ./...                # 25 tests, including the shared corpus
go vet ./... && gofmt -l .
go build ./cmd/secure-keystore
```

```
go/
├── doc.go          the package documentation, and Version
├── format.go       everything the format fixes
├── errors.go       Error, the codes, and the errors.Is sentinels
├── options.go      defaults and validation
├── crypto.go       PBKDF2, HKDF, AES-GCM — the only place a cipher is built
├── token.go        the stateless skv2 token
├── input.go        the three input formats, testable without a file
├── bundle.go       the .skb bundle
├── keystore.go     the store itself
└── cmd/secure-keystore/
```

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../conformance/](../conformance/)** — how cross-language compatibility is tested
- **[CHANGELOG.md](CHANGELOG.md)**

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
