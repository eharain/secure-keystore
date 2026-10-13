# Changelog

All notable changes to the .NET implementation are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

The **package version** and the **store format version** are separate numbers and
move at different speeds — see [SPEC.md §11](../SPEC.md#11-versioning). This is
package 3.0.0, writing store format 3.0.

## [3.0.0] - 2026-10-13

First release of the .NET implementation.

Written against [SPEC.md](../SPEC.md) rather than by reading another
implementation — which is the rule that let six of them agree — and tested against
the [shared conformance corpus](../conformance/), a set of fixtures the JavaScript
implementation produced.

Verified: 132 tests pass, including the shared corpus, the GCM cross-check described below, and reading stores written by the JavaScript and Go implementations.

### Added

- `Keystore`, the store: `secure`, `get`, `get_all`, `set`, `migrate`,
  `delete_key` and `delete_store`, in this language's spelling. A user key
  unlocks a per-store master key; the master key unlocks each value under its own
  salt.
- **One password stretch per store open**, not one per value. The user key is
  stretched with PBKDF2-HMAC-SHA256 at 600,000 rounds; value keys come from
  HKDF-SHA256, because a master key is not a password and stretching it buys
  nothing. See [SPEC.md §2.1](../SPEC.md#21-two-derivations-because-there-are-two-jobs).
- **Every value bound to its key name**, as GCM additional authenticated data and
  as HKDF context, so a value file moved to another key's name fails to decrypt.
- Metadata without a user key: listing stores, listing keys, and store info. Key
  names are not encrypted, which is what makes a store inspectable without a
  password — and means a key name must not itself be a secret.
- Export and import as one portable `.skb` bundle, with every name in it reduced
  to its base name before writing, because a bundle is an untrusted file that
  arrived over a wire.
- Stateless value tokens: `encrypt_value` and `decrypt_value`, writing `skv2` and
  reading both `skv2` and `skv1`. The iteration count is recorded in the token, so
  a column encrypted cheaply and a single secret encrypted expensively both read
  back.
- Reading format 2.0 stores, and `migrate` to carry one across to 3.0. A 2.0 store
  keeps taking 2.0 writes until it is migrated, so a store is never half one
  format and half the other.
- The three input formats — colon, dotenv and JSON — parseable from a string, with
  no directory involved.
- Errors carrying the codes in [SPEC.md §10](../SPEC.md#10-errors), identical in
  every implementation.
- A command line with the same verbs, flags and `--json` output as every other
  implementation.
- **Silence by default.** The library prints nothing unless given a logger, which
  is what lets it drop into an application that has opinions about its own
  logging.

### Fixed before release

- **The command line printed `????` for any non-ASCII value.**
  `Console.OutputEncoding` defaults to the Windows OEM code page, which cannot
  represent an emoji or a Cyrillic key name and substitutes a literal question
  mark. The library was correct throughout - its suite passed the corpus, unicode
  included - but a script capturing `get` output would have stored the
  corruption. Found by [`cross-test.mjs`](../conformance/cross-test.mjs), which
  is the only test that runs the six implementations against each other through
  their command lines.

### Notes specific to .NET

- `AesGcm`, `Rfc2898DeriveBytes.Pbkdf2` and `HKDF` from the framework, which is why this needs .NET 8. No package dependency.
- `LegacyGcm`, a narrow GCM implementation used **only** for the 16-byte nonce format 2.0 wrote, because `AesGcm.NonceByteSizes` is 12 to 12 and throws on anything else. Held against `AesGcm` on 12-byte nonces across 120 shape combinations, against NIST SP 800-38D test case 6, and against the corpus format 2.0 store.
- `[JsonPropertyName]` on every field, because `System.Text.Json` neither matches nor emits camelCase by default — without it a .NET store would carry `Iv` where everyone else writes `iv`.
- `[JsonExtensionData]` so unknown fields survive a rewrite, and `UnsafeRelaxedJsonEscaping` so a non-ASCII key name is written as itself rather than as `\uXXXX`.

[3.0.0]: https://github.com/eharain/secure-keystore/releases/tag/dotnet%2Fv3.0.0
