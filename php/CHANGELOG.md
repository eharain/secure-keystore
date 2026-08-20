# Changelog

All notable changes to the PHP implementation are recorded here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

The **package version** and the **store format version** are separate numbers and
move at different speeds — see [SPEC.md §11](../SPEC.md#11-versioning). This is
package 1.0.0, writing store format 3.0.

## [1.0.0] - 2026-08-20

First release of the PHP implementation.

Written against [SPEC.md](../SPEC.md) rather than by reading another
implementation — which is the rule that let six of them agree — and tested against
the [shared conformance corpus](../conformance/), a set of fixtures the JavaScript
implementation produced.

**Not verified.** Written against the specification, but not yet run on a machine with a PHP toolchain. See [ROADMAP.md §3](../ROADMAP.md#3-next--ci-across-all-six).

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

- **The store timestamp read the clock twice.** `now()` took the date from one
  sample of the clock and the milliseconds from another, so the two could
  disagree across a second boundary - rare, wrong, and very hard to reproduce.
  It also relied on an implicit float-to-int cast that PHP 8.3 deprecates, which
  is what drew attention to it.

### Notes specific to PHP

- `ext-openssl` and `ext-hash`, which ship with PHP. No Composer dependency.
- `hash_pbkdf2(..., true)` for raw bytes — without the final `true` the result is hex, at twice the length, and every derived key is wrong in a way that still works within one implementation and nowhere else.
- `hash_hkdf` is built in, so HKDF costs nothing extra.
- `openssl_decrypt` returns `false` rather than throwing; every result is checked, so a wrong key becomes `BAD_USER_KEY` rather than an empty string a caller might mistake for a value.
- The whole `master.json` document is kept, so unknown fields survive a rewrite.

[1.0.0]: https://github.com/eharain/secure-keystore/releases/tag/php%2Fv1.0.0
