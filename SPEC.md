# The secure-keystore format

**Store format 3.0.** Bundle format 1. Value token `skv2`.

This document is what an implementation is written against. Anything not
specified here is an implementation detail and may differ between languages;
anything specified here must not. Where an implementation and this document
disagree, this document is wrong and should be fixed — but say so, because until
it is fixed the other implementations are being written against the wrong thing.

Every implementation reads **3.0 and 2.0**, and writes 3.0. §9 says what a 2.0
store is and how it is carried forward.

---

## 1. What the format is for

Secrets that sit on disk, are read by an application at run time, and are
unreadable to anyone who has the files but not the key that opens them.

Three things are specified, and they are independent — an implementation may
provide any one without the others:

| | |
|---|---|
| **The store** | A directory of encrypted values that one *user key* opens. §4 |
| **The value token** | One self-describing encrypted string, no directory involved. §5 |
| **The backup bundle** | A whole store as one portable file. §6 |

---

## 2. Primitives

Every implementation uses exactly these. They are not negotiable, because a
store written by one must open in every other.

| | |
|---|---|
| **Cipher** | AES-256-GCM |
| **Authentication tag** | 16 bytes (128 bits), the GCM default |
| **Initialisation vector** | **12 bytes** |
| **Password stretching** | PBKDF2-HMAC-SHA256, 600,000 rounds by default (§2.2) |
| **Key derivation** | HKDF-SHA256 (§2.1) |
| **Derived key length** | 32 bytes (256 bits) |
| **Additional authenticated data** | a context string (§3) |
| **Binary encoding** | lowercase hex, in every field of every file |
| **Text encoding** | UTF-8, before encryption and after decryption |

Every salt and every IV is generated fresh from a cryptographically secure
random source, for every value, every time it is written. Nothing is derived
from a counter, a timestamp, or the key name.

**The 12-byte IV is not negotiable and is the reason 3.0 exists.** It is what
NIST SP 800-38D recommends, and it is the only length several platforms accept:
.NET's `System.Security.Cryptography.AesGcm` reports `NonceByteSizes` as 12 to 12
and throws on anything else, Go's `cipher.NewGCM` produces it and nothing else
without an explicit constructor, and Rust's `Aes256Gcm` is typed to it. Format
2.0 used 16 bytes, and every one of those platforms had to work around it.

### 2.1 Two derivations, because there are two jobs

This is the other thing 3.0 changed, and the one most worth understanding.

```
user key ──PBKDF2-SHA256(store salt, N rounds)──► user-derived key
master key ──HKDF-SHA256(value salt, context)──► value key
```

A **user key is a password**: chosen by a person, low entropy, and the only thing
standing between an attacker with the files and every secret in them. It is
stretched, deliberately and expensively.

A **master key is not a password**: it is already a strong secret, produced once
and never typed. Stretching it buys nothing — there is no low-entropy guess space
to slow an attacker down in — and costs a full PBKDF2 run per value. Format 2.0
did exactly that, which is why reading a twenty-key store took twenty PBKDF2 runs
and several seconds. HKDF is the primitive for deriving a key from key material,
and it is what 3.0 uses.

The practical consequence: **opening a store costs one password stretch, whatever
its size.** An implementation that runs PBKDF2 per value is not conforming, and
will be obvious from its timing.

### 2.2 Iteration counts

600,000 rounds is OWASP's 2023 guidance for PBKDF2-HMAC-SHA256, and the default
this format writes. It is a per-store parameter, recorded in the store, and an
implementation **must** use the recorded count rather than its own default.

An implementation should refuse a count below **10,000**. Test suites run at that
floor; nothing else should.

Where the count is absent — a record written before it was recorded — the reader
**must** assume **100,000**, which is what every 1.x and 2.x release used.

Deriving with the wrong count cannot produce a wrong plaintext: it produces a
wrong key, and the GCM tag then rejects it.

---

## 3. Context binding

Every encryption in this format is bound to a context string, passed as GCM
additional authenticated data. For a value it is *also* the HKDF `info`, so the
key itself differs per context.

| What is encrypted | Context |
|---|---|
| The store's master key | `secure-keystore:v3:master` |
| A value under key `K` | `secure-keystore:v3:value:` + `K` |
| A stateless value token | `secure-keystore:v3:token` |

The key name is appended as its UTF-8 bytes, unescaped and unmodified.

**This is what closes the gap format 2.0 had.** There, the tag covered the
ciphertext and nothing else, so anyone who could *write* to a store could swap
the contents of two `.enc` files and both would decrypt — under each other's
names, silently, with valid tags. Binding the key name means a swapped file
derives a different key *and* fails its tag.

The two mechanisms are deliberately redundant. Either alone would close the gap;
carrying both costs one string and means an implementation that forgets one is
still safe.

---

## 4. The store

### 4.1 Layout

```
<keystore-dir>/
├── index.json                 catalogue of stores — names and counts, no secrets
└── <store-name>/
    ├── master.json            store metadata and the encrypted master key
    └── <stem>-<hash>.enc      one file per value
```

A directory under `<keystore-dir>` is a store **if and only if** it contains a
`master.json`. A reader listing stores must apply that test and must not assume
every subdirectory is one.

### 4.2 The two layers

```
user key ──PBKDF2──► user-derived key ──AES-GCM(ctx: master)──► master key
master key ──HKDF(ctx: value:K)──► value key ──AES-GCM(ctx: value:K)──► value
```

The second layer is **not** defence in depth against a leaked user key. Anyone
holding the user key reaches every value, by design and in one step. What it buys
is that every value carries its own salt and its own derived key, so no two
values share any key material and rewriting one value touches one file.

### 4.3 `master.json`

```json
{
  "version": "3.0",
  "created": "2026-08-20T10:30:00.000Z",
  "updated": "2026-08-20T11:02:14.881Z",
  "salt": "<64 hex characters — 32 random bytes>",
  "iterations": 600000,
  "master": {
    "iv": "<24 hex characters — 12 random bytes>",
    "authTag": "<32 hex characters — 16 bytes>",
    "data": "<hex — the master key, encrypted>"
  },
  "entries": [
    { "key": "api_key", "file": "api_key-3f2a1b9c.enc" }
  ],
  "sourceFile": "keys.env",
  "totalKeys": 1
}
```

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | Store format version. `"3.0"` for this document. Absent means 1.0. |
| `created` | yes | ISO 8601, UTC, when the store was first written. |
| `updated` | no | ISO 8601, UTC, when it was last written. |
| `migrated` | no | ISO 8601, UTC, when it was last carried across formats. |
| `salt` | yes | Hex. The salt the user key is stretched with. 32 bytes. |
| `iterations` | yes in 3.0 | PBKDF2 rounds for the user key. Absent means 100,000. |
| `master` | yes | The master key, encrypted under the user-derived key, context `…:master`. |
| `entries` | yes | **Ordered** list of `{key, file}`. Order is insertion order. |
| `sourceFile` | no | Base name of the input file, for information only. |
| `totalKeys` | no | `entries.length`. Informational; a reader must trust `entries`. |

**Key names are stored in the clear.** That is deliberate — it is what lets a
store be listed and inspected without a password — and it means a key name must
never itself be a secret. See §8.1.

**An unrecognised field must be preserved on rewrite, not dropped.** A reader
that drops fields it does not know about will silently downgrade a store written
by a newer implementation. Every implementation carries the whole document.

### 4.4 Value files

One file per value, named `<stem>-<hash>.enc`:

- **`stem`** — the key's **UTF-8 bytes**, truncated to the first 64, with every
  byte outside `[A-Za-z0-9._-]` replaced by `_`.
- **`hash`** — the first 8 hex characters of `SHA-256(key)`, over the UTF-8 bytes
  of the original key name. **This is the identity.**

Both halves of that definition matter and both are byte-oriented on purpose. A
UTF-16 language that substitutes per *character* writes four underscores where
everyone else writes eight for a four-character Cyrillic key — the same store,
named differently depending on who wrote it. Truncation is by bytes for the same
reason; a multi-byte character straddling the limit is cut, which is harmless
because the stem is a label and the hash is the identity.

Sanitising is what stops a key named `../../.ssh/authorized_keys` from writing
outside the store. Sanitising alone would map `a/b` and `a_b` onto one file, so
the hash is what keeps them apart; hashing alone would produce filenames no one
can read.

```json
{
  "salt": "<64 hex characters — 32 random bytes>",
  "data": {
    "iv": "<24 hex characters — 12 bytes>",
    "authTag": "<32 hex characters>",
    "data": "<hex — the value, encrypted>"
  }
}
```

A 3.0 value record carries **no** `iterations` field: its key comes from HKDF,
which takes no count. Writing one would record a number nothing reads. (A 2.0
record does carry one — see §9.)

The authoritative list of values in a store is `master.json`'s `entries`. A
`.enc` file no entry names is an orphan and must be ignored, not adopted.

### 4.5 `index.json`

```json
{
  "stores": {
    "production": {
      "version": "3.0",
      "created": "2026-08-20T10:30:00.000Z",
      "totalKeys": 3,
      "keys": ["api_key", "jwt_secret", "db_url"],
      "sourceFile": "keys.env"
    }
  },
  "updated": "2026-08-20T11:02:14.881Z"
}
```

A convenience catalogue, holding nothing that is not also in each store's own
`master.json`. Every operation must read the store's own metadata for anything
that matters. A missing or corrupt `index.json` is recoverable by rebuilding it
and must never fail an operation on the store itself.

---

## 5. The value token

One string, encrypted under a user key, with no store behind it. For an
application that already has somewhere to put the value — a database column, a
config row — and wants it unreadable while it sits there.

```
skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>
```

Six colon-separated fields; every one after the count is lowercase hex:

| Field | Bytes | |
|---|---|---|
| `skv2` | — | Literal. The version of the token layout. |
| `iterations` | — | Decimal PBKDF2 rounds. **The fix `skv1` needed.** |
| `salt` | 16 | Random, per token. |
| `iv` | 12 | Random, per token. |
| `authTag` | 16 | The GCM tag. |
| `ciphertext` | any | The UTF-8 plaintext, encrypted. May be empty. |

The key is `PBKDF2-HMAC-SHA256(userKey, salt, iterations, 32)`, and the context
is `secure-keystore:v3:token`.

**Why the count is in the token.** `skv1` had no field for it, so its cost is
frozen at 100,000 forever — there is no way to write a stronger token that an
older reader could still identify, and no way for a reader to know what a token
in front of it was derived with. A format that cannot say how it was made is a
format that can never change.

It also makes the cost *tunable*, which matters here more than in a store: a
store pays one stretch however many keys it holds, but a token pays one **per
value**. Encrypting a column of ten thousand rows at 600,000 rounds is hours.
Lower the count for bulk work; the token records what was chosen.

Behaviour that is part of the contract:

- Encrypting a null or empty value returns the input unchanged. This is what lets
  the function be mapped over a record without first sorting the empty fields out
  of it.
- Decrypting a value that is **not** a token returns it unchanged, so a column
  part way through being encrypted can be read with one call.
- Decrypting a value that **is** a token but is malformed, truncated, altered, or
  was written under a different user key **must fail**. It must never be passed
  through: doing so hands the caller ciphertext it believes is plaintext.

### 5.1 `skv1`, read only

```
skv1:<salt>:<iv>:<authTag>:<ciphertext>
```

Five fields; 16-byte salt, 16-byte IV, exactly 100,000 rounds, and **no
additional authenticated data**. Every implementation must read it. None writes
it.

---

## 6. The backup bundle

A whole store as one JSON file, conventionally `.skb`.

```json
{
  "format": "secure-keystore-backup",
  "version": 1,
  "storeName": "production",
  "files": {
    "master.json": "<the file's exact bytes, as a string>",
    "api_key-3f2a1b9c.enc": "<the file's exact bytes, as a string>"
  }
}
```

Every file in the store directory goes in verbatim. The contents are already
encrypted, so a bundle is safe to move through a CI artifact store or an `scp`
and useless to anyone who intercepts it without the user key. A bundle carries
whatever store format its files are in, which is why the bundle version did not
change with 3.0.

A reader **must**:

1. Refuse a file that is not JSON, saying so.
2. Refuse a document whose `format` is not `secure-keystore-backup`.
3. Refuse a `version` greater than it understands, with `UNSUPPORTED_FORMAT`,
   rather than reading what it recognises and discarding the rest.
4. Refuse a bundle with no `master.json`.
5. **Reduce every name in `files` to its base name before writing it**, treating
   both `/` and `\` as separators whatever the host platform, and stripping a
   drive prefix. A bundle is an untrusted file that arrived over a wire, and
   `"../../.ssh/authorized_keys"` is a bundle somebody can write by hand.

A bundle does not record the user key, and importing one does not verify it. The
first `get` is what tells you whether the store you deployed is one you can open
— which is why a deploy should end with one.

---

## 7. Input files

The formats a store can be created from. These describe plaintext that exists
only before the store does, so an implementation may support any subset — but
where it supports one, it must parse it this way.

The format follows the file extension, case-insensitively.

### `.txt` and anything else — colon format

```
master:MySuperSecretMasterKey
api_key:sk_live_abc123
db_url:postgres://user:pass@host:5432/db
```

The first non-empty line must be `master:<value>`; anything else is an error.
Lines are trimmed, empty lines skipped, and a line with no colon skipped. **Only
the first colon splits**, so a value may contain as many more as it likes.

### `.env` — dotenv

```sh
# comments are skipped
master=MySuperSecretMasterKey
export api_key=sk_live_abc123
jwt_secret="quoted values are unquoted"
```

`KEY=value`, one per line. Lines beginning `#` are skipped, as are lines with no
`=` and lines with an empty key. A leading `export ` is stripped. A matched pair
of single or double quotes around the whole value is stripped — no escape
sequences are interpreted. The `master` entry may appear anywhere.

### `.json` — a flat object

```json
{ "master": "MySuperSecretMasterKey", "api_key": "sk_live_abc123", "port": 8080 }
```

Must be an object; an array or a scalar is an error. The `master` property is the
master key. A value that is not a string is serialised to its compact JSON form,
so `8080` is stored as `"8080"` and `true` as `"true"` — everything in a store is
a string. Entry order is the document's order.

---

## 8. What this format does not protect

Stated here rather than left to be discovered, because an implementation that
claims more than this is claiming something false.

### 8.1 Key names are not secret

`index.json` and `master.json` list them in the clear. Anyone with read access to
the directory learns that a store has an `aws_secret_access_key` in it, though
not what it is. Do not encode a secret into a key name.

### 8.2 The user key is the whole root of trust

There is one secret. If it leaks, every value in every store it opens is
readable. The second encryption layer does not change this.

### 8.3 Everything else

No audit log, no key rotation of the *user* key without a rewrite, no dynamic or
short-lived secrets, no protection against a compromised host, no defence against
side channels, and no FIPS validation. A decrypted value is plaintext in process
memory for as long as the application holds it.

> **Closed in 3.0.** Format 2.0 did not bind a value to its key name, so anyone
> with write access to a store could swap two `.enc` files and both would decrypt
> under the wrong names. §3 closes that. A 2.0 store still on disk still has the
> gap — migrate it.

---

## 9. Format 2.0, and carrying it forward

Every implementation reads 2.0. It differs from 3.0 in exactly four ways:

| | 2.0 | 3.0 |
|---|---|---|
| IV length | 16 bytes | 12 bytes |
| Value key | PBKDF2 over the master key | HKDF over the master key |
| `iterations` on a value record | present, and used | absent |
| Additional authenticated data | none | the context string (§3) |

A `version` of `"2.0"`, `"1.0"`, or absent means the legacy shape. 1.0 and 2.0
have the same on-disk layout — 2.0 only added optional fields — so both take the
same path.

**A store is never half one format and half the other.** Writing to a 2.0 store
writes a 2.0 record, keeping it internally consistent. `migrate` is what moves
the whole store across: it decrypts every value with the old parameters and
rewrites it with the new ones, under a fresh store salt and fresh per-value
salts. The master key does not change, so nothing outside the store has to be
told.

`migrate` must decrypt everything before writing anything, so that a wrong user
key leaves the store untouched, and must write every value file before
`master.json`, so that an interruption leaves the store readable in its old
format.

Running `migrate` on a store already at 3.0 re-encrypts it — which is how a
store's iteration count is raised.

### 9.1 Refusing the future

An implementation must refuse a **major** version it does not know, with
`UNSUPPORTED_FORMAT`, rather than reading the parts it recognises. A minor bump
adds an optional field and must remain readable.

---

## 10. Errors

Every implementation reports failures with these codes. The message may be
reworded between releases and between languages; the code may not. A shell script
that greps for `BAD_USER_KEY` must keep working when the service is rewritten in
another language.

| Code | |
|---|---|
| `INVALID_OPTIONS` | The options given do not make sense. |
| `INVALID_ARGUMENT` | A required argument was missing or empty. |
| `STORE_NOT_FOUND` | No such store under this keystore directory. |
| `STORE_CORRUPT` | The directory exists but is not a store, or its metadata is unreadable. |
| `KEY_NOT_FOUND` | No such key — in the named store, or in any of them. |
| `BAD_USER_KEY` | Decryption failed: wrong key, tampered bytes, or mismatched context. |
| `BAD_TOKEN` | A value token is not in the form §5 defines. |
| `BAD_INPUT` | The input file is not readable as the format its extension claims. |
| `BAD_BACKUP` | The bundle is missing, unreadable, or not a keystore bundle. |
| `UNSUPPORTED_FORMAT` | The store or bundle is newer than this build reads. |

GCM cannot distinguish a wrong key from tampered bytes from mismatched
additional data — all three are a tag that does not verify — so all three are
`BAD_USER_KEY`. An implementation must not attempt to tell them apart.

---

## 11. Versioning

Three version numbers, deliberately separate, because they change at different
speeds:

| | Where | Changes when |
|---|---|---|
| **Store format** | `master.json` → `version` | The directory layout or a file's shape changes. |
| **Token layout** | the `skv2` prefix | The token's fields change. |
| **Bundle format** | the bundle's `version` | The bundle's shape changes. |
| *(Implementation)* | each package's own version | Anything ships. Not part of this document. |

A **minor** bump adds an optional field; a reader of the older version must still
open the store. A **major** bump may break compatibility, and must be refused by
a reader that does not know it.

---

## 12. Conformance

An implementation conforms if:

1. It reads a store, a token and a bundle written by any other conforming
   implementation, and returns identical plaintext.
2. What it writes is read back identically by any other conforming
   implementation.
3. It reads format 2.0 stores and `skv1` tokens.
4. It refuses everything §6 says to refuse, and fails everywhere §5 says to fail,
   with the codes in §10.
5. It never returns a wrong plaintext. Where it cannot return the right one, it
   fails.

Byte-for-byte identical *output* is explicitly **not** required and cannot be:
every write draws fresh random salts and IVs, so no two encryptions of the same
value agree anywhere. The conformance suite is therefore **a corpus of fixtures
written once and decrypted by everyone**, plus a cross-write check in each
direction — not a comparison of encoders. See
[conformance/README.md](conformance/README.md).
