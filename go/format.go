package securekeystore

// Wire-format constants for the secure-keystore format.
//
// Nothing here is a tuning knob. These are the values that define what a store
// written by this package looks like, and changing one changes what the other
// five implementations can read - which is why they live in one file rather
// than scattered through the code that happens to use them.
//
// Two format versions appear throughout. 3.0 is what this build writes; 2.0 is
// what earlier releases wrote and what this build still reads. Everywhere the
// two differ, the legacy value is named *Legacy and the difference is a
// parameter rather than a separate code path.

const (
	// StoreFormatVersion is stamped into every master.json this build writes.
	StoreFormatVersion = "3.0"
	// StoreFormatLegacy is the older format this build still reads and, on a
	// store already written that way, still writes.
	StoreFormatLegacy = "2.0"
)

const (
	// BackupFormat identifies an export bundle. It is checked before anything is
	// written to disk, so a file that merely happens to be JSON is refused
	// rather than half-imported.
	BackupFormat = "secure-keystore-backup"
	// BackupVersion is the bundle format this build writes and the highest it
	// reads.
	BackupVersion = 1
)

// Value token layouts. skv2 records its own iteration count, which is the one
// thing skv1 got wrong: a token that cannot say how it was derived is a token
// whose parameters can never change.
//
//	skv1:<salt>:<iv>:<authTag>:<ciphertext>
//	skv2:<iterations>:<salt>:<iv>:<authTag>:<ciphertext>
const (
	TokenPrefix       = "skv2"
	tokenParts        = 6
	TokenPrefixLegacy = "skv1"
	tokenPartsLegacy  = 5
)

// Cryptographic parameters.
const (
	// keyLength is 32 bytes - AES-256.
	keyLength = 32
	// ivLength is 12 in format 3.0, which is what NIST SP 800-38D recommends for
	// GCM and what cipher.NewGCM produces without argument. ivLengthLegacy is
	// the 16 that 2.0 wrote, and the reason this package has to reach for
	// cipher.NewGCMWithNonceSize at all.
	ivLength       = 12
	ivLengthLegacy = 16
	// authTagLength is the GCM default and the only length this format uses.
	authTagLength = 16
)

// PBKDF2 iteration counts. These apply to the user key, which is a password.
// A value key is derived with HKDF and takes no count.
const (
	// DefaultIterations is what a new store stretches the user key with, and
	// follows OWASP's 2023 guidance for PBKDF2-HMAC-SHA256.
	DefaultIterations = 600000
	// MinIterations is the floor below which the option is refused. Test suites
	// run at this; nothing else should.
	MinIterations = 10000
	// legacyIterations is assumed for any 2.0 record written before the count
	// was recorded.
	legacyIterations = 100000
	// tokenIterationsLegacy is fixed by the skv1 layout, which has no field to
	// record a count in.
	tokenIterationsLegacy = 100000
)

// Salt lengths, in bytes.
const (
	storeSaltLength = 32
	valueSaltLength = 32
	// tokenSaltLength is 16 because the token carries its salt inline, in hex,
	// in every stored value. It is fixed by the layout rather than by taste.
	tokenSaltLength = 16
)

// Domain-separation contexts, used as GCM additional authenticated data and,
// for a value, as the HKDF info as well.
//
// This is what closes the gap 2.0 had: there, the tag covered the ciphertext
// and nothing else, so anyone who could write to a store could swap two value
// files and both would decrypt - under each other's names.
const (
	contextMaster      = "secure-keystore:v3:master"
	contextValuePrefix = "secure-keystore:v3:value:"
	contextToken       = "secure-keystore:v3:token"
)

// valueContext is the full context string binding a value to its key name.
func valueContext(keyName string) string {
	return contextValuePrefix + keyName
}

// Filenames inside a keystore directory.
const (
	indexFile      = "index.json"  // catalogue of stores: names and key names, no secrets
	masterFile     = "master.json" // per-store metadata and the encrypted master key
	valueExtension = ".enc"        // one authenticated-encrypted file per value
)

const (
	// DefaultKeystoreDirname is created under the working directory when no
	// KeystoreDir is given.
	DefaultKeystoreDirname = ".keystore"
	// DefaultBackupExtension is what ExportStore writes when given no path.
	DefaultBackupExtension = ".skb"
	// masterEntryKey is the name an input file uses for the master key, in
	// every input format.
	masterEntryKey = "master"
)

// Value filenames are a readable stem plus a hash of the key. The stem may
// collide between two different keys; the hash is what keeps their files apart.
const (
	filenameStemLimit  = 64
	filenameHashLength = 8 // hex characters
)
