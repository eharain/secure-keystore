package securekeystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// The cryptographic primitives, and nothing else.
//
// Every AES call in this package goes through this file, so there is exactly
// one place where an algorithm, an IV length or an encoding is chosen.
//
// Two derivations, for two different jobs, which format 2.0 conflated:
//
//	stretchPassword  a password into a key. Deliberately slow. Used once per
//	                 store, on the user key, and on every value token.
//	deriveFromKey    a key into another key. Fast, because the input is already
//	                 high-entropy key material and stretching it buys nothing.

// encrypted is one AES-GCM result, as it appears in a store file. Every field
// is lowercase hex.
type encrypted struct {
	IV      string `json:"iv"`
	AuthTag string `json:"authTag"`
	Data    string `json:"data"`
}

// randomBytes panics only if the system random source has failed, which is not
// a condition any caller can do anything useful about.
func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, wrapf(CodeInvalidArgument, err, "could not read %d random bytes", n)
	}
	return buf, nil
}

// stretchPassword is PBKDF2-HMAC-SHA256: a password, stretched.
//
// The count is a parameter rather than a constant because it is recorded
// alongside whatever it derives. Deriving with a count that does not match the
// one a record was written with produces a different key, and the GCM tag then
// rejects it - which is the failure you want rather than the one where it
// nearly works.
func stretchPassword(password string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLength)
	if err != nil {
		return nil, wrapf(CodeInvalidArgument, err, "could not derive a key")
	}
	return key, nil
}

// deriveFromKey is HKDF-SHA256: one key into another, bound to a context.
//
// The input is the master key, which is already a strong secret, so there is
// nothing to stretch - the job is separation, not hardening. info carries the
// context that separates them, and for a value that context contains the key
// name, which is half of what stops two value files being swapped. The other
// half is the same string passed as GCM additional data.
func deriveFromKey(key string, salt []byte, info string) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, []byte(key), salt, info, keyLength)
	if err != nil {
		return nil, wrapf(CodeInvalidArgument, err, "could not derive a value key")
	}
	return derived, nil
}

// aead builds the GCM mode for a given IV length.
//
// Format 3.0 uses 12 bytes, which is what cipher.NewGCM produces and what every
// other platform accepts. Format 2.0 used 16, which needs the explicit
// constructor - and which is exactly why 3.0 changed it.
func aead(key []byte, ivLen int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapf(CodeInvalidArgument, err, "could not build the cipher")
	}
	if ivLen == ivLength {
		return cipher.NewGCM(block)
	}
	return cipher.NewGCMWithNonceSize(block, ivLen)
}

// encryptWith seals a plaintext under a fresh random IV, so the same plaintext
// under the same key never produces the same bytes twice.
//
// aad may be empty, which is how a format 2.0 record is written: it bound
// nothing.
func encryptWith(plaintext, aad string, key []byte, ivLen int) (encrypted, error) {
	gcm, err := aead(key, ivLen)
	if err != nil {
		return encrypted{}, err
	}

	iv, err := randomBytes(ivLen)
	if err != nil {
		return encrypted{}, err
	}

	var additional []byte
	if aad != "" {
		additional = []byte(aad)
	}

	// Seal appends the tag to the ciphertext; the format stores them apart.
	sealed := gcm.Seal(nil, iv, []byte(plaintext), additional)
	split := len(sealed) - gcm.Overhead()

	return encrypted{
		IV:      hex.EncodeToString(iv),
		AuthTag: hex.EncodeToString(sealed[split:]),
		Data:    hex.EncodeToString(sealed[:split]),
	}, nil
}

// decryptWith reverses encryptWith, and translates the failure.
//
// GCM cannot tell a wrong key from tampered bytes from mismatched additional
// data - all three are a tag that does not verify - so all three become
// CodeBadUserKey, with the crypto package's own error kept as the cause.
func decryptWith(record encrypted, aad string, key []byte, what string) (string, error) {
	iv, err := hex.DecodeString(record.IV)
	if err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "the %s has a malformed iv", what)
	}
	tag, err := hex.DecodeString(record.AuthTag)
	if err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "the %s has a malformed authTag", what)
	}
	data, err := hex.DecodeString(record.Data)
	if err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "the %s has malformed ciphertext", what)
	}
	if len(iv) == 0 {
		return "", failf(CodeStoreCorrupt, "the %s has an empty iv", what)
	}

	gcm, err := aead(key, len(iv))
	if err != nil {
		return "", err
	}

	var additional []byte
	if aad != "" {
		additional = []byte(aad)
	}

	plaintext, err := gcm.Open(nil, iv, append(data, tag...), additional)
	if err != nil {
		return "", wrapf(CodeBadUserKey, err,
			"could not decrypt the %s: the key is wrong, or the stored bytes have been altered", what)
	}
	return string(plaintext), nil
}

// safeFileName builds a filesystem-safe, collision-resistant filename for a key.
//
// The stem is for humans, so it is the key with anything unsafe replaced -
// which neutralises "../", drive letters and the characters Windows refuses.
// Sanitising alone would map "a/b" and "a_b" onto one file, so the real
// identity is the hash suffix; the stem is only a label.
//
// The stem is truncated by *bytes*, matching every other implementation. A
// multi-byte character straddling the limit would be cut, but the name is a
// label and the hash is the identity, so a mangled label costs nothing.
func safeFileName(key string) string {
	var stem strings.Builder
	for i := 0; i < len(key) && stem.Len() < filenameStemLimit; i++ {
		c := key[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
			stem.WriteByte(c)
		default:
			stem.WriteByte('_')
		}
	}

	sum := sha256.Sum256([]byte(key))
	return stem.String() + "-" + hex.EncodeToString(sum[:])[:filenameHashLength] + valueExtension
}
