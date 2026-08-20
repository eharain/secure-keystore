# secure-keystore — PHP

**Encrypted secrets at rest, with no service to run.** No Composer
dependencies — `ext-openssl` and `ext-hash` are all it needs.

[![Packagist](https://img.shields.io/badge/packagist-tech--style%2Fsecure--keystore-F28D1A.svg)](https://packagist.org/packages/tech-style/secure-keystore)
[![PHP](https://img.shields.io/badge/php-8.1%2B-777BB4.svg)](https://www.php.net/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
composer require tech-style/secure-keystore
```

```php
use TechStyle\SecureKeystore\Keystore;

$store = new Keystore();
$store->secure('./keys.env', getenv('USER_KEY'), 'production');
$apiKey = $store->get('api_key', getenv('USER_KEY'), 'production');
```

This is one of [six implementations](../README.md#one-format-six-languages) of the
[secure-keystore format](../SPEC.md). A store written here opens in the
JavaScript, Go, .NET, Python and Rust ones, and the other way round — which is not
a claim but [a test](tests/ConformanceTest.php) against a corpus the JavaScript
implementation produced, and against
[`cross-test.mjs`](../conformance/cross-test.mjs), where all six write stores and
all six read every one of them.

---

## Two ways in

**A store** — a directory of encrypted values that one user key opens.

**A token** — one string in, one string out, nothing on disk.

```php
use TechStyle\SecureKeystore\ValueToken;

$token = ValueToken::encrypt('sk_live_abc123', $userKey);
$back = ValueToken::decrypt($token, $userKey);
```

---

## API

### `new Keystore(?string $keystoreDir, int $iterations, ?callable $logger, bool $createDir)`

Binds one keystore directory and one set of options, validated once in the
constructor. The instance holds no secret: the user key is passed to each call
that needs one and is never retained.

```php
$store = new Keystore(
    keystoreDir: '/var/lib/app/keys',
    iterations: 600000,
    logger: static fn (string $line) => error_log($line),
);
```

| Argument | Default | |
|---|---|---|
| `$keystoreDir` | `./.keystore` | Where stores live. |
| `$iterations` | `600000` | PBKDF2 rounds for the *user key*, on new and migrated stores. Recorded in the store. Does not apply to value keys, which use HKDF. |
| `$logger` | `null` | Called with one line of progress. **Null means the package prints nothing** — the default, and what an application wants. |
| `$createDir` | `true` | Create the keystore directory if absent. |

### Store operations

```php
$store->secure(string $inputFile, string $userKey, ?string $storeName = null): array
$store->get(string $key, string $userKey, ?string $storeName = null): string
$store->getAll(string $userKey, string $storeName): array
$store->set(string $key, string $value, string $userKey, string $storeName): array
$store->migrate(string $storeName, string $userKey): array
$store->deleteKey(string $key, string $storeName): void
$store->deleteStore(string $storeName): void
```

`getAll` costs **one** PBKDF2 derivation however many keys the store holds — see
[SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).

### Metadata — no user key needed

```php
$store->listStores(): array
$store->listKeys(string $storeName): array
$store->getStoreInfo(string $storeName): array
```

Key names live in metadata in the clear, so **a key name must not itself be a
secret**.

### Bundles and tokens

```php
$store->exportStore(string $storeName, ?string $backupPath = null): string
$store->importStore(string $backupPath, ?string $storeName = null): string

ValueToken::encrypt(?string $plaintext, string $userKey, ?int $iterations = null): ?string
ValueToken::decrypt(mixed $token, string $userKey): mixed
ValueToken::isEncryptedValue(mixed $value): bool
ValueToken::tokenVersion(mixed $value): ?string
```

`$iterations` lowers the cost for bulk work — a token pays one stretch **per
value**, unlike a store. The count is recorded in the token, so decryption follows
whatever was chosen.

---

## Errors

Every failure is a `KeystoreException` with a stable code:

```php
use TechStyle\SecureKeystore\ErrorCodes;
use TechStyle\SecureKeystore\KeystoreException;

try {
    $store->get('api_key', $userKey, 'production');
} catch (KeystoreException $error) {
    if ($error->getErrorCode() === ErrorCodes::BAD_USER_KEY) {
        // wrong password, tampered bytes, or a mismatched context
    }
}
```

The codes are identical in all six implementations —
[SPEC.md §10](../SPEC.md#10-errors).

`getErrorCode()` rather than `getCode()`, because `Exception::getCode()` is an
`int` and cannot carry a string.

---

## Notes specific to PHP

**`openssl_decrypt` returns `false` rather than throwing.** That is the failure
mode this package exists to convert: a wrong user key becomes `BAD_USER_KEY`,
naming the store, rather than an empty string a caller might mistake for a value.
Every decryption result is checked before it is returned.

**`hash_pbkdf2` needs its final `true`.** Without it the result is hex, at twice
the length, and every derived key is wrong in a way that still "works" within one
implementation and nowhere else.

**`hash_hkdf` is built in**, so HKDF costs nothing extra — one of the reasons this
port needs no Composer dependency at all.

**`openssl_encrypt` hands the tag back through a by-reference parameter**, which
matches how the format stores it — no splitting, unlike Go, Python and Rust.

---

## The CLI

```bash
vendor/bin/secure-keystore get api_key "$USER_KEY" production
```

Same verbs, flags, error codes and `--json` output as every other
implementation — see the [root README](../README.md#the-cli).

---

## Development

```bash
composer install
composer test               # includes the shared corpus
```

```
php/
├── src/
│   ├── Format.php            everything the format fixes
│   ├── ErrorCodes.php        the codes, shared with every implementation
│   ├── KeystoreException.php
│   ├── Crypto.php            PBKDF2, HKDF, AES-GCM — the only place a cipher is built
│   ├── ValueToken.php        the stateless skv2 token
│   ├── InputFile.php         the three input formats, testable without a file
│   ├── Bundle.php            the .skb bundle
│   └── Keystore.php          the store itself
├── bin/secure-keystore
└── tests/
```

`composer.lock` is not committed: this is a library, and the lock file of a
library binds nobody.

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../conformance/](../conformance/)** — how cross-language compatibility is tested
- **[CHANGELOG.md](CHANGELOG.md)**

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
