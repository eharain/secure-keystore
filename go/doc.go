// Package securekeystore is encrypted secrets at rest, with no service to run.
//
// Two ways in, for different things:
//
//  1. A store. A directory of encrypted values that one user key opens. The
//     store owns a master key, one salt per value, and a catalogue - so an
//     application deploys a directory and reads secrets out of it at run time.
//     That is [Keystore].
//  2. A token. One string in, one string out, nothing on disk. The application
//     already has somewhere to put it - a database column, a config row - and
//     only wants the value unreadable while it sits there. That is
//     [EncryptValue] and [DecryptValue].
//
// Both use the same primitives: AES-256-GCM to encrypt, PBKDF2-HMAC-SHA256 to
// stretch the user key, HKDF-SHA256 to derive a value key from the master key.
// A fresh random salt and IV every time.
//
//	store, err := securekeystore.New()
//	err = store.Secure("./keys.env", os.Getenv("USER_KEY"), "production")
//	apiKey, err := store.Get("api_key", os.Getenv("USER_KEY"), "production")
//
// # Which KDF, and why two
//
// A user key is a password, so it is stretched: deliberately slow, 600,000
// rounds by default. A master key is not a password - it is already a strong
// secret - so value keys come from HKDF, which is fast. Stretching the master
// key once per value, which format 2.0 did, costs seconds on a store of any
// size and buys nothing the master key did not already have.
//
// # The format
//
// The on-disk format is specified in SPEC.md at the root of the repository, and
// this implementation reads and writes the same bytes as the JavaScript, Python,
// .NET, PHP and Rust ones. That is not a claim but a test: all six run the same
// conformance corpus, and this package's copy is in conformance_test.go.
//
// This build writes format 3.0 and reads 3.0 and 2.0. A 2.0 store keeps taking
// 2.0 writes until [Keystore.Migrate] moves the whole thing across, so a store
// is never half one format and half the other.
//
// # Dependencies
//
// None. crypto/aes, crypto/cipher, crypto/pbkdf2 and crypto/hkdf are all in the
// standard library, which is why this package needs Go 1.24 or later.
package securekeystore

// Version is the version of this implementation, which is not the same thing as
// the version of the store format ([StoreFormatVersion]).
const Version = "3.0.0"
