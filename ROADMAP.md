# Roadmap

Where secure-keystore is, and where it goes next.

This project borrowed its structure from
[json-compress](https://github.com/eharain/JSON-Compress) — the same shape of
thing, one format with an implementation on every registry — and the lessons
below are the ones that transferred. They are named where they applied, because
the argument for doing something in a particular order is more useful than the
item itself.

**Status: format 3.0, six implementations, all six verified against each other.**

---

## The five lessons, and what each one cost

json-compress reached six byte-compatible implementations. What made that
possible, and what it looked like when applied here:

**1. The specification came before the second implementation.**
[SPEC.md](SPEC.md) was written first, and every implementation after JavaScript
was written against the document rather than by reading the JavaScript. Go, .NET,
Python, PHP and Rust each passed the corpus without any of them having read
another implementation's source.

**2. A shared corpus decides disputes.** It also *finds* them.
[conformance/](conformance/) caught a filename divergence — JavaScript sanitised
per UTF-16 character, everyone else per UTF-8 byte — that was invisible in any
single implementation and obvious the moment two of them wrote the same store.
The spec now fixes the definition in bytes and JavaScript was the one that
changed.

**3. Platform differences surface at the port.** Here they surfaced *before* it,
by reading the docs: .NET's `AesGcm` will not accept the 16-byte IV that format
2.0 used. That is what drove §2 below, and doing it first is what stopped five
implementations being written twice.

**4. The library must not print.** 1.x `console.log`-ed through every operation,
which made it unusable from anything with opinions about its own logging. 2.0
fixed it, and it had to be fixed *before* the ports, or five implementations
inherit it. All six now take a logger and are silent without one.

**5. Publish under one scope, one name story.** Six packages, six registries, one
specification, one set of error codes.

---

## 1. Done — format 3.0

Three changes, all needing a format bump, so they shipped together.

### 1.1 A 12-byte IV

NIST recommends it; .NET's `AesGcm` *requires* it; Go's `cipher.NewGCM` and
Rust's `Aes256Gcm` produce it by default. Format 2.0's 16 bytes made every one of
those platforms reach for a workaround, and in .NET's case for a hand-written GCM
just to read old data.

### 1.2 The key name bound as AAD, and as HKDF info

Format 2.0's GCM tag covered the ciphertext and nothing else, so anyone with
*write* access to a store could swap two `.enc` files and both would decrypt,
under each other's names, silently. [SPEC.md §3](SPEC.md#3-context-binding)
closes it, twice over.

### 1.3 The right KDF for each job

This is the change that was not on the original plan, and the one with the
largest practical effect. Format 2.0 ran PBKDF2 over the **master key**, once per
value — a password KDF applied to something that was never a password. Raising
the count to OWASP's 600,000 would have made a twenty-key store take ten seconds
to open.

3.0 stretches the *user key* at 600,000 rounds and derives value keys with
HKDF-SHA256. Opening a store now costs **one** password stretch whatever its
size. The JavaScript test suite runs 3.7× faster than it did at one sixth the
iteration count.

### 1.4 Migration

`migrate` rewrites a whole store in the current format, under fresh salts. It
decrypts everything before writing anything, so a wrong user key leaves the store
untouched. Running it on a store already at 3.0 re-encrypts it, which is how a
store's iteration count is raised. A 2.0 store keeps taking 2.0 writes until it
is migrated, so a store is never half one format and half the other.

---

## 2. Done — one package per registry

| Language | Registry | Package | CLI | Own suite |
|---|---|---|---|---|
| **JavaScript** | npm | `@tech-style/secure-keystore` | ✅ | 84 tests |
| **Go** | Go modules | `github.com/eharain/secure-keystore/go` | ✅ | 25 tests |
| **.NET** | NuGet | `TechStyle.SecureKeystore` | ✅ | 132 tests |
| **Python** | PyPI | `secure-keystore` | ✅ | 28 tests |
| **PHP** | Packagist | `tech-style/secure-keystore` | ✅ | 8 tests, 112 assertions |
| **Rust** | crates.io | `secure-keystore` | ✅ | 11 tests |

All six pass their own suites and the shared fixture corpus. All six also read
every other's stores, tokens and bundles — see §3.

### What is identical across all six

- **The verbs.** `secure`, `get`, `all`, `set`, `migrate`, `list`, `stores`,
  `info`, `delete`, `delete-store`, `export`, `import`, `encrypt`, `decrypt`.
- **The error codes.** `BAD_USER_KEY` means the same thing in every language.
- **The `--json` output**, field for field. A shell script should not be able to
  tell which implementation it is calling.
- **The flags.** `--keystore`, `--iterations`, `--json`, `--quiet`.

### What is deliberately not

Everything idiomatic. Python raises `KeystoreError`; Go returns an `error` with
`errors.Is` sentinels; Rust returns `Result`; .NET throws `KeystoreException`.
.NET is `PascalCase` and Python is `snake_case`. json-compress made the opposite
mistake once — a faithful port that read as a translation rather than as a
library — and it was worth not repeating.

### One place a platform genuinely forced a decision

.NET cannot read format 2.0 through `System.Security.Cryptography.AesGcm`, which
refuses any nonce but 12 bytes. Rather than take a BouncyCastle dependency in a
library that otherwise has none, it carries a narrow GCM implementation used only
for legacy nonce lengths — held against the platform's own `AesGcm` on 12-byte
nonces across 120 shape combinations, and against NIST SP 800-38D test case 6.
See [dotnet/README.md](dotnet/README.md).

---

## 3. Done — the cross-implementation matrix

The fixture corpus pins one direction: bytes written once, by JavaScript,
decrypted by everyone. That catches a *reader* that is wrong. It cannot catch a
**writer** that is wrong in a way its own reader agrees with — the two halves of
one implementation can be consistently, privately incorrect, and the corpus would
never know.

[`conformance/cross-test.mjs`](conformance/cross-test.mjs) closes that:

```bash
node conformance/cross-test.mjs
```

Every implementation writes a store, a token and a bundle; every implementation
reads all of them. It drives the *command lines* rather than the libraries,
because the CLI is the one interface all six share — so it tests the format, the
verbs, the flags and the `--json` contract in one pass.

Current result, with all six runnable:

| | |
|---|---|
| Reader/writer combinations | **36**, all ok |
| Cross-language migrations | **30** — each store migrated by every *other* implementation, then read back by all six |
| Values per combination | 13, including empty, `:::`, emoji, CJK, 3,000 characters, and a string that looks like a token |
| Wrong-key attempts | **36**, every one refused with `BAD_USER_KEY` |

### What it caught

Two bugs the per-language suites could not see, because both were in the last six
inches — between a correct value and a terminal:

- **The .NET CLI printed `????`** for any non-ASCII value.
  `Console.OutputEncoding` defaults to the OEM code page on Windows, so an emoji
  or a Cyrillic key name came back visibly correct from five implementations and
  corrupted from the sixth. A script capturing that output would have stored the
  corruption.
- **The Python CLI raised `UnicodeEncodeError`** on the same values, because
  stdout defaults to cp1252 on Windows. It could store a secret it could not
  show.

Neither touched a store — both implementations' library suites passed the corpus,
unicode included, throughout. Only running the six against each other *through
their command lines* surfaced them.

---

## 4. Next — CI

The matrix passes on one machine. It needs to stay passing:

- A GitHub Actions job per implementation, every push, against the corpus.
- One job running `conformance/cross-test.mjs` with all six built.
- Publish jobs per registry, gated on both being green.

---

## 5. Later — things that need a design first

Not scheduled, because each needs a decision made before it needs code.

- **User-key rotation without a full rewrite.** `migrate` re-encrypts under a new
  *derivation*; changing the user key itself currently means the same thing. The
  mechanics are easy; doing it atomically, so an interrupted rotation leaves a
  readable store, is the part that needs design.
- **Argon2id as an alternative to PBKDF2.** What a new design would use. The cost
  is a dependency in every language, where PBKDF2 and HKDF are in five of the six
  standard libraries — which is exactly why 3.0 did not do it.
- **Audit log.** Which key was read, when, by which process. Cheap to add, and
  the thing that would make this usable where a compliance regime is watching.
- **An in-memory cache with a TTL.** The most-requested-shaped feature and the
  most dangerous: it means holding a derived key in memory, and that trade belongs
  to the application, not the library. 3.0 removed most of the reason for it —
  opening a store is now one stretch, not one per value.
- **A read-only store handle** that opens the master key once and cannot write.
  Useful in a server that reads secrets at boot and should not be able to modify
  them afterwards.
- **Browser and edge runtimes** via WebCrypto — same format, `SubtleCrypto`
  instead of `node:crypto`. PBKDF2, HKDF and AES-GCM are all there. A separate
  entry point rather than a separate package.
- **`age` / GPG recipients** as an alternative to a user key, so a store can be
  opened by any of several people without their sharing one password.

---

## 6. Explicitly not doing

Saying no in the document is cheaper than saying it in five issue threads.

- **A server, a daemon, or a network protocol.** The entire value of this is that
  there is nothing to run. Where a secrets service is wanted, HashiCorp Vault and
  the cloud KMSes exist and are better at it.
- **Dynamic or short-lived secrets.** Same reason. That is a service's job.
- **Compliance claims.** No FIPS validation, no HIPAA or SOC 2 statement. The
  primitives are standard, the format is documented, and the limits are in
  [SPEC.md §8](SPEC.md#8-what-this-format-does-not-protect) — an auditor can read
  all of it. Nobody should be told it is certified.
- **Hiding key names.** They are in the clear, deliberately: it is what makes a
  store inspectable without a password. An implementation that encrypts them is
  writing a different format.
- **Guessing the user key from the environment.** No implicit `USER_KEY` lookup
  inside any library. It is passed in at every call site, so it is always visible
  in the code where a secret is being opened.
- **Writing format 2.0 in new stores.** It is read, and written only into stores
  already in it. There is no option to create one.
