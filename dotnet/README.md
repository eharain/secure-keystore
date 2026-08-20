# secure-keystore — .NET

**Encrypted secrets at rest, with no service to run.** No dependencies —
`AesGcm`, `Rfc2898DeriveBytes` and `HKDF` are all in the framework.

[![NuGet](https://img.shields.io/badge/nuget-TechStyle.SecureKeystore-004880.svg)](https://www.nuget.org/packages/TechStyle.SecureKeystore)
[![.NET](https://img.shields.io/badge/.NET-8.0%2B-512BD4.svg)](https://dotnet.microsoft.com/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
dotnet add package TechStyle.SecureKeystore
dotnet tool install -g TechStyle.SecureKeystore.Cli
```

```csharp
using TechStyle.SecureKeystore;

var store = new Keystore();
var apiKey = store.Get("api_key", Environment.GetEnvironmentVariable("USER_KEY")!, "production");
```

This is one of [six implementations](../README.md#one-format-six-languages) of the
[secure-keystore format](../SPEC.md). A store written here opens in the
JavaScript, Go, Python, PHP and Rust ones, and the other way round — which is not
a claim but [a test](tests/TechStyle.SecureKeystore.Tests/ConformanceTests.cs)
against a corpus the JavaScript implementation produced.

**.NET 8 or later**, the lowest version with both `HKDF` and `AesGcm`.

---

## Two ways in

**A store** — a directory of encrypted values that one user key opens.

**A token** — one string in, one string out, nothing on disk.

```csharp
var token = ValueToken.Encrypt("sk_live_abc123", userKey);
var back = ValueToken.Decrypt(token, userKey);
```

---

## API

### `new Keystore(KeystoreOptions?)`

Binds one keystore directory and one set of options, validated once in the
constructor. The instance holds no secret: the user key is passed to each call
that needs one and is never retained.

```csharp
var store = new Keystore(new KeystoreOptions
{
    KeystoreDir = "/var/lib/app/keys",
    Iterations = 600_000,
    Logger = message => logger.LogInformation("{Message}", message),
});
```

| Property | Default | |
|---|---|---|
| `KeystoreDir` | `./.keystore` | Where stores live. |
| `Iterations` | `600000` | PBKDF2 rounds for the *user key*, on new and migrated stores. Recorded in the store. Does not apply to value keys, which use HKDF. |
| `Logger` | `null` | Called with one line of progress. **Null means the library prints nothing** — the default, and what a server wants. |
| `CreateDir` | `true` | Create the keystore directory if absent. |

### Store operations

```csharp
SecureResult Secure(string inputFile, string userKey, string? storeName = null);
string Get(string key, string userKey, string? storeName = null);
Dictionary<string, string> GetAll(string userKey, string storeName);
SetResult Set(string key, string value, string userKey, string storeName);
MigrateResult Migrate(string storeName, string userKey);
void DeleteKey(string key, string storeName);
void DeleteStore(string storeName);
```

`GetAll` costs **one** PBKDF2 derivation however many keys the store holds — see
[SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).

### Metadata — no user key needed

```csharp
IReadOnlyList<string> ListStores();
IReadOnlyList<string> ListKeys(string storeName);
StoreInfo GetStoreInfo(string storeName);
```

Key names live in metadata in the clear, so **a key name must not itself be a
secret**.

### Bundles and tokens

```csharp
string ExportStore(string storeName, string? backupPath = null);
string ImportStore(string backupPath, string? storeName = null);

static string? ValueToken.Encrypt(string? plaintext, string userKey, TokenOptions? options = null);
static string? ValueToken.Decrypt(string? token, string userKey);
static bool ValueToken.IsEncryptedValue(string? value);
static string? ValueToken.TokenVersion(string? value);
```

---

## Errors

Every failure is a `KeystoreException` with a stable `Code`:

```csharp
try
{
    store.Get("api_key", userKey, "production");
}
catch (KeystoreException error) when (error.Code == ErrorCodes.BadUserKey)
{
    // wrong password, tampered bytes, or a mismatched context
}
```

The codes are identical in all six implementations —
[SPEC.md §10](../SPEC.md#10-errors). A wrong user key would otherwise surface as
`AuthenticationTagMismatchException`, which names neither the store nor the
reason.

---

## The one place .NET forced a decision

`System.Security.Cryptography.AesGcm` reports `NonceByteSizes` as **12 to 12** and
throws on anything else. That is fine for format 3.0, which uses a 12-byte IV
precisely so every platform can use its own AEAD — but **format 2.0 used 16
bytes**, and every implementation has to keep reading 2.0 stores.

The options were a BouncyCastle dependency in a library that otherwise has none,
or a narrow GCM implementation for legacy nonce lengths only. This package does
the latter, in [`LegacyGcm.cs`](src/TechStyle.SecureKeystore/LegacyGcm.cs), and
holds it to two independent checks:

- **Against the platform.** On 12-byte nonces, where both can run, `LegacyGcm` and
  `AesGcm` must agree byte for byte — ciphertext and tag — across three key
  lengths, ten plaintext lengths and four associated-data lengths. 120
  combinations, both directions.
- **Against NIST.** SP 800-38D test case 6, the published vector with a
  non-96-bit nonce — exactly the path `AesGcm` cannot reach.
- **Against the other implementations.** The conformance corpus contains a format
  2.0 store written by JavaScript, and reading it exercises the 16-byte J0
  derivation end to end.

`Crypto` routes 12-byte work to `AesGcm` and only ever falls back for legacy
records. Nothing new is written with it. It exists to read the past, not to extend
it — and `Migrate` is how a caller stops needing it:

```csharp
store.Migrate("production", userKey);   // 2.0 → 3.0, onto the platform AEAD
```

---

## Other notes specific to .NET

**JSON property names are spelled out.** `System.Text.Json` neither matches nor
emits camelCase by default, so without explicit `[JsonPropertyName]` a .NET store
would carry `Iv` where every other implementation writes `iv` — and would read
neither. (This was caught by the conformance corpus, on the first run.)

**Unknown fields survive a rewrite**, via `[JsonExtensionData]`, because an older
reader that silently downgrades a store written by a newer implementation is
worse than one that refuses it.

**Non-ASCII goes in as itself.** The writer uses
`JavaScriptEncoder.UnsafeRelaxedJsonEscaping`, so a Cyrillic key name is written
as its characters rather than as `\uXXXX` escapes — matching what the other five
write, and keeping a store file readable.

---

## The CLI

```bash
dotnet tool install -g TechStyle.SecureKeystore.Cli
```

Same verbs, flags, error codes and `--json` output as every other
implementation — see the [root README](../README.md#the-cli).

---

## Development

```bash
dotnet test                 # 132 tests, including the corpus and the GCM cross-check
dotnet build
```

```
dotnet/
├── src/TechStyle.SecureKeystore/
│   ├── Format.cs             everything the format fixes
│   ├── KeystoreException.cs  the exception and its codes
│   ├── Crypto.cs             PBKDF2, HKDF, AES-GCM — the only place a cipher is built
│   ├── LegacyGcm.cs          GCM for the one nonce length .NET will not do
│   ├── ValueToken.cs         the stateless skv2 token
│   ├── InputFile.cs          the three input formats
│   ├── Bundle.cs             the .skb bundle
│   ├── Keystore.cs           the store itself
│   └── KeystoreOptions.cs    options and result records
├── src/TechStyle.SecureKeystore.Cli/
└── tests/TechStyle.SecureKeystore.Tests/
```

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../conformance/](../conformance/)** — how cross-language compatibility is tested
- **[CHANGELOG.md](CHANGELOG.md)**

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
