package securekeystore

import (
	"os"
	"path/filepath"
)

// Options is what a keystore is allowed to do.
//
// The zero value is not a usable set of options - KeystoreDir would be empty
// and Iterations zero - so build one from [DefaultOptions] and change what you
// need:
//
//	options := securekeystore.DefaultOptions()
//	options.KeystoreDir = "/var/lib/app/keys"
//	store, err := securekeystore.New(options)
//
// Options are validated once, in [New], rather than on every call, so a mistake
// surfaces where it was written instead of as a store that quietly ends up
// somewhere unexpected.
type Options struct {
	// KeystoreDir is where stores live. Default ./.keystore.
	KeystoreDir string
	// Iterations is the PBKDF2 count the *user key* is stretched with, for new
	// and migrated stores. It is recorded in the store, so raising it never
	// orphans one written before. Default 600,000.
	//
	// It does not apply to value keys, which are derived with HKDF and take no
	// count.
	Iterations int
	// Logger is called with one line of progress. Nil means the package prints
	// nothing at all, which is the default and what a server wants.
	Logger func(string)
	// CreateDir creates the keystore directory if it is absent.
	CreateDir bool
}

// DefaultOptions returns the options used when none are given.
func DefaultOptions() Options {
	dir := DefaultKeystoreDirname
	if wd, err := os.Getwd(); err == nil {
		dir = filepath.Join(wd, DefaultKeystoreDirname)
	}

	return Options{
		KeystoreDir: dir,
		Iterations:  DefaultIterations,
		Logger:      nil,
		CreateDir:   true,
	}
}

// Validate checks that the options make sense, so that a mistake surfaces at
// the call site rather than as a store in the wrong place.
func (o Options) Validate() error {
	if o.KeystoreDir == "" {
		return failf(CodeInvalidOptions, "KeystoreDir must be a non-empty path - build options from DefaultOptions()")
	}
	if o.Iterations < MinIterations {
		return failf(CodeInvalidOptions,
			"Iterations must be at least %d, not %d - build options from DefaultOptions()",
			MinIterations, o.Iterations)
	}
	return nil
}

// resolveOptions takes the variadic options every constructor accepts and
// returns one validated set. More than one is a programming error rather than a
// merge: the second would silently win.
func resolveOptions(options []Options) (Options, error) {
	switch len(options) {
	case 0:
		return DefaultOptions(), nil
	case 1:
		if err := options[0].Validate(); err != nil {
			return Options{}, err
		}
		return options[0], nil
	default:
		return Options{}, failf(CodeInvalidOptions, "expected at most one set of options, got %d", len(options))
	}
}
