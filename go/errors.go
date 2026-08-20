package securekeystore

import (
	"errors"
	"fmt"
)

// One error type, with a code.
//
// The code is what the other five implementations agree on: BadUserKey means
// the same thing in Go, Python, .NET, PHP, Rust and JavaScript, and a script
// that greps for it keeps working when the team rewrites the service. The
// message may be reworded between releases; the code will not be.
//
// Every sentinel below works with errors.Is, so the idiomatic Go check and the
// cross-language code are the same check:
//
//	if errors.Is(err, securekeystore.ErrBadUserKey) { ... }
//	if ks.CodeOf(err) == "BAD_USER_KEY" { ... }

// Code is a stable identifier for a class of failure.
type Code string

// The codes this package can report. They are identical in every
// implementation of the format.
const (
	// CodeInvalidOptions - the options given do not make sense.
	CodeInvalidOptions Code = "INVALID_OPTIONS"
	// CodeInvalidArgument - a required argument was missing or empty.
	CodeInvalidArgument Code = "INVALID_ARGUMENT"
	// CodeStoreNotFound - no such store under this keystore directory.
	CodeStoreNotFound Code = "STORE_NOT_FOUND"
	// CodeStoreCorrupt - the directory exists but is not a store, or its
	// metadata is unreadable.
	CodeStoreCorrupt Code = "STORE_CORRUPT"
	// CodeKeyNotFound - no such key, in the named store or in any of them.
	CodeKeyNotFound Code = "KEY_NOT_FOUND"
	// CodeBadUserKey - decryption failed: the key is wrong, or the bytes have
	// been altered.
	CodeBadUserKey Code = "BAD_USER_KEY"
	// CodeBadToken - a value token is not in the form this format defines.
	CodeBadToken Code = "BAD_TOKEN"
	// CodeBadInput - the input file is not readable as the format its extension
	// claims.
	CodeBadInput Code = "BAD_INPUT"
	// CodeBadBackup - the bundle is missing, unreadable, or not one of ours.
	CodeBadBackup Code = "BAD_BACKUP"
	// CodeUnsupportedFormat - the store or bundle is in a format version newer
	// than this build reads.
	CodeUnsupportedFormat Code = "UNSUPPORTED_FORMAT"
)

// Sentinels, so that errors.Is works the way a Go caller expects.
var (
	ErrInvalidOptions    = &Error{Code: CodeInvalidOptions}
	ErrInvalidArgument   = &Error{Code: CodeInvalidArgument}
	ErrStoreNotFound     = &Error{Code: CodeStoreNotFound}
	ErrStoreCorrupt      = &Error{Code: CodeStoreCorrupt}
	ErrKeyNotFound       = &Error{Code: CodeKeyNotFound}
	ErrBadUserKey        = &Error{Code: CodeBadUserKey}
	ErrBadToken          = &Error{Code: CodeBadToken}
	ErrBadInput          = &Error{Code: CodeBadInput}
	ErrBadBackup         = &Error{Code: CodeBadBackup}
	ErrUnsupportedFormat = &Error{Code: CodeUnsupportedFormat}
)

// Error is returned by every operation in this package that can fail in a way
// the caller might want to handle rather than merely report.
type Error struct {
	// Code is stable across releases and identical across implementations.
	Code Code
	// Message says what happened, in words meant for a person.
	Message string
	// Cause is the underlying error, when there was one. A GCM failure keeps
	// the crypto package's own error here.
	Cause error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("secure-keystore: %s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause, so errors.Is and errors.As reach it.
func (e *Error) Unwrap() error { return e.Cause }

// Is matches on the code alone, which is what makes the sentinels above work
// against an error carrying a message and a cause.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other.Code == e.Code
}

// CodeOf reports the code an error carries, or the empty string if it did not
// come from this package.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func failf(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func wrapf(code Code, cause error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Cause: cause}
}
