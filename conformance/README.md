# Conformance

Two tests, answering two different questions.

```bash
node conformance/generate.js       # rebuild the fixtures
node conformance/cross-test.mjs    # every implementation reads every other's output
```

| | Question it answers |
|---|---|
| **The corpus** — `manifest.json` + `fixtures/` | *Does this implementation read what the others wrote?* Bytes written once, by JavaScript, decrypted by everyone. |
| **The matrix** — `cross-test.mjs` | *Does what this implementation writes read anywhere else?* All six write, all six read all of it. |

The second exists because the first cannot catch a **writer** that is wrong in a
way its own reader agrees with. The two halves of one implementation can be
consistently, privately incorrect, and a corpus of somebody else's bytes would
never notice.

---

## Why fixtures rather than a diff of encoders

json-compress — the sibling project this one borrowed its structure from — could
settle any cross-language dispute by compressing the same document in two
languages and comparing the bytes. **That test does not exist here.** Every write
in this format draws a fresh salt and a fresh IV, so two implementations
encrypting the same secret never produce the same bytes, and neither do two runs
of the same implementation. There is nothing to diff.

So the corpus runs the other way round: **written once, decrypted by everyone.**

| | |
|---|---|
| `manifest.json` | What every implementation's test suite reads. Fixtures, expected plaintext, and the refusal cases. |
| `fixtures/stores/` | Whole keystores, including one in format 2.0. |
| `fixtures/bundles/` | Export bundles, including a hostile one. |
| `generate.js` | Rebuilds all of it from the JavaScript implementation. |

Three things are checked, and the last two matter as much as the first:

1. **These bytes decrypt to these values.** Every store, every token, every
   bundle, in every language.
2. **These bytes are refused.** A tampered ciphertext, an edited iteration count,
   a bundle that tries to write outside its directory, a format version from the
   future. An implementation that accepts one of these is not conforming however
   well it handles the happy path.
3. **A cross-write.** Each implementation writes a store holding the corpus's own
   awkward values and reads it back, which is what catches a writer that is
   self-consistent and wrong.

---

## What is in it, and why

The values were chosen to break things:

| | |
|---|---|
| `empty` | The empty string, stored as a value. |
| `colons`, `delimited` | The format's own delimiter, inside a value. |
| `unicode` | Cyrillic, Latin-1 and CJK, past the BMP. |
| `newlines` | CR, LF and CRLF. |
| `long` | 5,000 characters, well past one AES block. |
| `looks_like_token` | A plain string beginning `skv2:`, which must not be mistaken for a token. |
| `spaces` | Leading and trailing whitespace, which trimming would eat. |

And the key *names* separately, in `awkward-keys`:

| | |
|---|---|
| `a/b` and `a_b` | Two names that sanitise to the same stem and must not collide. |
| `../escape` | A traversal attempt in a key name. |
| `ключ` | A non-ASCII name — the case that caught a real bug (see below). |
| 80 × `k` | Past the 64-byte stem limit. |

Plus:

- **`legacy-2.0`** — a store written the way format 2.0 wrote one: 16-byte IV, no
  additional authenticated data, PBKDF2 per value. Every implementation must
  still read it, and .NET must reach for a non-platform GCM to do so.
- **`legacy-skv1`** — a token in the old five-field layout.
- **`future-format`** — a store claiming format 9.0, which must be refused.

## The matrix

`cross-test.mjs` drives the **command lines** rather than the libraries, because
the CLI is the one interface all six share — so one run tests the format, the
verbs, the flags and the `--json` contract together.

Each implementation writes a store (13 awkward values, set one at a time), a
token, and an export bundle. Then every implementation reads all of it, migrates
each of the others' stores, and is handed a wrong user key to make sure it says
no.

```
  reader      javascript  go          dotnet      python      php         rust
  ------------------------------------------------------------------------------
  javascript  ok          ok          ok          ok          ok          ok
  go          ok          ok          ok          ok          ok          ok
  dotnet      ok          ok          ok          ok          ok          ok
  python      ok          ok          ok          ok          ok          ok
  php         ok          ok          ok          ok          ok          ok
  rust        ok          ok          ok          ok          ok          ok

  30 migrations, each read back by all 6: all ok
  36 attempts with a wrong key: all refused with BAD_USER_KEY
```

It runs whatever is runnable and skips the rest, so it is useful on a machine
with two implementations built and on CI with all six. Point it at built binaries
with `SK_JAVASCRIPT`, `SK_GO`, `SK_DOTNET`, `SK_PYTHON`, `SK_PHP`, `SK_RUST`.

---

## What these have already caught

**Filename generation disagreed across languages.** JavaScript replaced unsafe
*characters* while every other implementation replaced unsafe *bytes*, so the key
`ключ` produced `____-1de36a32.enc` in one and `________-1de36a32.enc` in the
rest. Reads were unaffected — the filename is recorded in `master.json` and the
hash is the identity — but two implementations writing the same new key produced
different files. [SPEC.md §4.4](../SPEC.md#44-value-files) now fixes the
definition in UTF-8 bytes, and JavaScript was the one that changed.

**Two command lines could store a secret they could not print.** The .NET CLI
wrote `????` for any non-ASCII value, because `Console.OutputEncoding` defaults
to the Windows OEM code page; the Python CLI raised `UnicodeEncodeError` on the
same values, because stdout defaults to cp1252. Both libraries were correct
throughout — their own suites passed the corpus, emoji included. Only running the
six against each other *through their command lines* surfaced it, and a script
capturing that output would have stored the corruption.

**A PHP timestamp read the clock twice.** `now()` took the date from one sample
and the milliseconds from another, so the two could disagree across a second
boundary. Found because PHP 8.3 deprecated the implicit float-to-int cast the
arithmetic relied on — the toolchain complaining about one thing and revealing
another.

Each of these was invisible in any single implementation and obvious the moment
two of them met.

---

## Adding a case

Edit `generate.js`, run it, and run every implementation's suite. A case is worth
adding if it would plausibly differ between languages — string encodings, numeric
formatting, path handling, empty and boundary values — and not worth adding if it
only exercises one implementation's internals.

The counts are deliberately low (10,000 PBKDF2 rounds). The corpus is decrypted
on every CI run in six languages, and 600,000 rounds times that is minutes of
nothing. The iteration count is not what is under test; the format is.

## Running it

Each implementation runs the corpus as part of its own suite:

| | | Result |
|---|---|---|
| JavaScript | `cd javascript && npm test` | 84 tests |
| Go | `cd go && go test ./...` | 25 tests |
| .NET | `cd dotnet && dotnet test` | 132 tests |
| Python | `cd python && pytest` | 28 tests |
| PHP | `cd php && composer test` | 8 tests, 112 assertions |
| Rust | `cd rust && cargo test` | 11 tests |

Each skips with a clear message if the corpus has not been generated.

The matrix needs the command lines built:

```bash
(cd go   && go build -o secure-keystore ./cmd/secure-keystore)
(cd rust && cargo build --bin secure-keystore)
(cd dotnet && dotnet build src/TechStyle.SecureKeystore.Cli)

node conformance/cross-test.mjs
```
