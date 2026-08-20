package securekeystore

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// Encryption with no store behind it.
//
// The rest of this package owns a directory. These functions own nothing: they
// take a secret and a user key and give back a string, which the caller puts
// wherever it already keeps things - a database column, a config row, a queue
// message. There is no master key and no file, so there is also no keystore to
// deploy alongside the application.
//
// The token is self-describing, and says so in its first field:
//
//	skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>     all hex after the count
//	skv1:<salt>:<iv>:<authTag>:<ciphertext>                  read only
//
// What skv1 lacked was a field for its iteration count, which is why its count
// is frozen at 100,000 forever and skv2's is not.

// TokenOptions configures [EncryptValue].
type TokenOptions struct {
	// Iterations is the PBKDF2 count. Zero means [DefaultIterations].
	//
	// Unlike a store, there is no master key here: every token is stretched
	// straight from the user key, so the default cost is paid on every single
	// value. Encrypting a whole column is the case where that matters, and this
	// is the field for it - the count is recorded in the token, so decryption
	// follows whatever was chosen.
	Iterations int
}

// IsEncryptedValue reports whether s is a token this format defines, of either
// version.
func IsEncryptedValue(s string) bool {
	return strings.HasPrefix(s, TokenPrefix+":") || strings.HasPrefix(s, TokenPrefixLegacy+":")
}

// TokenVersion returns "skv2", "skv1", or the empty string if s is not a token.
func TokenVersion(s string) string {
	if !IsEncryptedValue(s) {
		return ""
	}
	return s[:strings.IndexByte(s, ':')]
}

// EncryptValue encrypts one string under a user key, with nothing on disk.
//
// A fresh random salt stretches the key and a fresh random IV feeds AES-256-GCM,
// so encrypting the same secret twice gives two different tokens - which is what
// stops a database column from revealing which rows share a value.
//
// The empty string is returned unchanged, matching every other implementation,
// so this can be mapped over a record without first sorting the empty fields
// out of it.
func EncryptValue(plaintext, userKey string, options ...TokenOptions) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if userKey == "" {
		return "", failf(CodeInvalidArgument, "EncryptValue requires a userKey")
	}

	iterations := DefaultIterations
	if len(options) > 1 {
		return "", failf(CodeInvalidArgument, "expected at most one set of options, got %d", len(options))
	}
	if len(options) == 1 && options[0].Iterations != 0 {
		iterations = options[0].Iterations
	}
	if iterations < MinIterations {
		return "", failf(CodeInvalidArgument, "iterations must be at least %d, not %d", MinIterations, iterations)
	}

	salt, err := randomBytes(tokenSaltLength)
	if err != nil {
		return "", err
	}

	key, err := stretchPassword(userKey, salt, iterations)
	if err != nil {
		return "", err
	}

	record, err := encryptWith(plaintext, contextToken, key, ivLength)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		TokenPrefix,
		strconv.Itoa(iterations),
		hex.EncodeToString(salt),
		record.IV,
		record.AuthTag,
		record.Data,
	}, ":"), nil
}

// DecryptValue reverses [EncryptValue], for either token version.
//
// Anything that is not a token is returned unchanged, so a column part way
// through being encrypted can be read with one call rather than a conditional at
// every site. A token that is malformed, altered, or written under a different
// user key returns an error - that case is never silently passed through,
// because doing so would hand the caller ciphertext it believed was plaintext.
func DecryptValue(token, userKey string) (string, error) {
	if !IsEncryptedValue(token) {
		return token, nil
	}
	if userKey == "" {
		return "", failf(CodeInvalidArgument, "DecryptValue requires a userKey")
	}

	parts := strings.Split(token, ":")
	legacy := parts[0] == TokenPrefixLegacy

	expected := tokenParts
	if legacy {
		expected = tokenPartsLegacy
	}
	if len(parts) != expected {
		return "", failf(CodeBadToken,
			"not a %s token: expected %d colon-separated fields, found %d", parts[0], expected, len(parts))
	}

	var (
		iterations int
		saltHex    string
		record     encrypted
		aad        string
	)

	if legacy {
		// skv1 has no iteration field, and every one ever written used 100,000.
		// It also predates additional authenticated data and the 12-byte IV;
		// both are read as they were written.
		iterations = tokenIterationsLegacy
		saltHex = parts[1]
		record = encrypted{IV: parts[2], AuthTag: parts[3], Data: parts[4]}
	} else {
		count, err := strconv.Atoi(parts[1])
		if err != nil || count < 1 {
			return "", failf(CodeBadToken, "token iteration count is not a positive whole number: %q", parts[1])
		}
		iterations = count
		saltHex = parts[2]
		record = encrypted{IV: parts[3], AuthTag: parts[4], Data: parts[5]}
		aad = contextToken
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", wrapf(CodeBadToken, err, "token salt is not hex")
	}

	key, err := stretchPassword(userKey, salt, iterations)
	if err != nil {
		return "", err
	}

	return decryptWith(record, aad, key, "value")
}
