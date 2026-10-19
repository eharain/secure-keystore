# secure-keystore — Python

**Encrypted secrets at rest, with no service to run.** One dependency:
[`cryptography`](https://cryptography.io/).

[![PyPI](https://img.shields.io/badge/pypi-secure--keystore-3775A9.svg)](https://pypi.org/project/secure-keystore/)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![licence](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)
[![format](https://img.shields.io/badge/format-3.0-6366f1.svg)](../SPEC.md)

```bash
pip install secure-keystore
```

```python
import os
from secure_keystore import Keystore

store = Keystore()
store.secure("./keys.env", os.environ["USER_KEY"], "production")
api_key = store.get("api_key", os.environ["USER_KEY"], "production")
```

This is one of [six implementations](../README.md#one-format-six-languages) of the
[secure-keystore format](../SPEC.md). A store written here opens in the
JavaScript, Go, .NET, PHP and Rust ones, and the other way round — which is not a
claim but [a test](tests/test_conformance.py) against a corpus the JavaScript
implementation produced, and against
[`cross-test.mjs`](../conformance/cross-test.mjs), where all six write stores and
all six read every one of them.

## Video

[![Secure Keystore: encrypted secrets at rest, with no service to run](https://raw.githubusercontent.com/eharain/secure-keystore/main/docs/media/video-thumbnail.jpg)](https://www.youtube.com/watch?v=ai-yHqZS_G4)

A 0:59 introduction on YouTube, with English captions.

---

## Two ways in

**A store** — a directory of encrypted values that one user key opens.

**A token** — one string in, one string out, nothing on disk.

```python
from secure_keystore import encrypt_value, decrypt_value

token = encrypt_value("sk_live_abc123", user_key)
back = decrypt_value(token, user_key)
```

---

## API

### `Keystore(keystore_dir=None, *, iterations=600_000, logger=None, create_dir=True)`

Binds one keystore directory and one set of options, validated once here rather
than on every call. The instance holds no secret: the user key is passed to each
call that needs one and is never retained.

| Argument | Default | |
|---|---|---|
| `keystore_dir` | `./.keystore` | Where stores live. |
| `iterations` | `600000` | PBKDF2 rounds for the *user key*, on new and migrated stores. Recorded in the store. Does not apply to value keys, which use HKDF. |
| `logger` | `None` | Called with one line of progress. **None means the package prints nothing** — the default, and what a server wants. |
| `create_dir` | `True` | Create the keystore directory if absent. |

### Store operations

```python
store.secure(input_file, user_key, store_name=None) -> SecureResult
store.get(key, user_key, store_name=None) -> str
store.get_all(user_key, store_name) -> dict[str, str]
store.set(key, value, user_key, store_name) -> SetResult
store.migrate(store_name, user_key) -> MigrateResult
store.delete_key(key, store_name) -> None
store.delete_store(store_name) -> None
```

`get_all` costs **one** PBKDF2 derivation however many keys the store holds — see
[SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).

### Metadata — no user key needed

```python
store.list_stores() -> list[str]
store.list_keys(store_name) -> list[str]
store.get_store_info(store_name) -> StoreInfo
```

Key names live in metadata in the clear, so **a key name must not itself be a
secret**.

### Bundles and tokens

```python
store.export_store(store_name, backup_path=None) -> str
store.import_store(backup_path, store_name=None) -> str

encrypt_value(plaintext, user_key, *, iterations=None) -> str | None
decrypt_value(token, user_key) -> str
is_encrypted_value(value) -> bool
token_version(value) -> str | None
```

`iterations` lowers the cost for bulk work — a token pays one stretch **per
value**, unlike a store. The count is recorded in the token, so decryption
follows whatever was chosen.

---

## Errors

Every failure is a `KeystoreError` with a stable `.code`:

```python
from secure_keystore import ErrorCodes, KeystoreError

try:
    store.get("api_key", user_key, "production")
except KeystoreError as error:
    if error.code == ErrorCodes.BAD_USER_KEY:
        ...   # wrong password, tampered bytes, or a mismatched context
    if error.code == ErrorCodes.STORE_NOT_FOUND:
        ...   # not deployed yet
```

The codes are identical in all six implementations —
[SPEC.md §10](../SPEC.md#10-errors). A wrong user key would otherwise surface as
`cryptography.exceptions.InvalidTag`, which names neither the store nor the
reason.

---

## Notes specific to Python

**`AESGCM` handles both nonce lengths.** `cryptography` accepts a 16-byte nonce as
well as the 12-byte one format 3.0 uses, so reading a format 2.0 store needs no
special case here — unlike .NET, where it needs a whole GCM implementation. Do not
let that make the 16-byte IV look fine; see
[ROADMAP.md §1.1](../ROADMAP.md#11-a-12-byte-iv).

**`AESGCM.encrypt` appends the tag** to the ciphertext; the format stores them as
separate hex fields, so the last 16 bytes are split off.

**Type hints throughout**, and a `py.typed` marker, so `mypy` sees the API.

**Ordering.** `entries` is a list and stays one; `dict` preserves insertion order
in the versions this supports, so a parsed input file keeps the document's key
order.

---

## The CLI

```bash
secure-keystore get api_key "$USER_KEY" production
python -m secure_keystore --help          # the same thing, without the entry point
```

Same verbs, flags, error codes and `--json` output as every other
implementation — see the [root README](../README.md#the-cli).

---

## Development

```bash
pip install -e ".[dev]"
pytest                      # includes the shared corpus
```

```
python/
├── src/secure_keystore/
│   ├── __init__.py       the public surface, and ALGORITHMS
│   ├── _format.py        everything the format fixes
│   ├── errors.py         KeystoreError and its codes
│   ├── _crypto.py        PBKDF2, HKDF, AES-GCM — the only place a cipher is built
│   ├── token.py          the stateless skv2 token
│   ├── input_file.py     the three input formats, testable without a file
│   ├── bundle.py         the .skb bundle
│   ├── keystore.py       the store itself
│   └── cli.py
└── tests/
```

## Further reading

- **[../SPEC.md](../SPEC.md)** — the format, in enough detail to implement it
- **[../conformance/](../conformance/)** — how cross-language compatibility is tested
- **[CHANGELOG.md](CHANGELOG.md)**

## Licence

MIT © [Tech Style Ltd](https://tech-style.co/)
