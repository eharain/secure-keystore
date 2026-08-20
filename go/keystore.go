package securekeystore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The store: a directory, and the operations on it.
//
// Two layers of encryption, and it is worth being precise about what the second
// one buys. A user key unlocks the master key; the master key unlocks each
// value. That is not defence in depth against a leaked user key - anyone
// holding the user key reaches everything - it is what lets every value carry
// its own salt and its own derived key, so no two values on disk share any
// material and re-keying one value touches one file.
//
// This build writes format 3.0 and reads 3.0 and 2.0. A store is never half one
// and half the other: writing to a 2.0 store keeps writing 2.0 records until
// Migrate moves the whole thing across.

// entryRef names one value and the file it lives in.
type entryRef struct {
	Key  string `json:"key"`
	File string `json:"file"`
}

// metadata is a store's master.json.
//
// It round-trips unknown fields through `extra`, because a store written by a
// newer implementation must not be silently downgraded by an older one that
// happens to write to it.
type metadata struct {
	Version    string
	Created    string
	Updated    string
	Migrated   string
	Salt       string
	Iterations int
	Master     encrypted
	Entries    []entryRef
	SourceFile string
	TotalKeys  int

	extra map[string]json.RawMessage
}

// knownFields are the ones the struct above covers; everything else is carried
// in `extra`.
var knownFields = map[string]bool{
	"version": true, "created": true, "updated": true, "migrated": true,
	"salt": true, "iterations": true, "master": true, "entries": true,
	"sourceFile": true, "totalKeys": true,
}

func (m *metadata) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	m.extra = make(map[string]json.RawMessage)
	for name, value := range raw {
		if !knownFields[name] {
			m.extra[name] = value
			continue
		}

		var err error
		switch name {
		case "version":
			err = json.Unmarshal(value, &m.Version)
		case "created":
			err = json.Unmarshal(value, &m.Created)
		case "updated":
			err = json.Unmarshal(value, &m.Updated)
		case "migrated":
			err = json.Unmarshal(value, &m.Migrated)
		case "salt":
			err = json.Unmarshal(value, &m.Salt)
		case "iterations":
			err = json.Unmarshal(value, &m.Iterations)
		case "master":
			err = json.Unmarshal(value, &m.Master)
		case "entries":
			err = json.Unmarshal(value, &m.Entries)
		case "sourceFile":
			err = json.Unmarshal(value, &m.SourceFile)
		case "totalKeys":
			err = json.Unmarshal(value, &m.TotalKeys)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (m metadata) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(m.extra)+10)
	for name, value := range m.extra {
		out[name] = value
	}

	put := func(name string, value any) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		out[name] = encoded
		return nil
	}

	fields := []struct {
		name  string
		value any
		omit  bool
	}{
		{"version", m.Version, m.Version == ""},
		{"created", m.Created, m.Created == ""},
		{"updated", m.Updated, m.Updated == ""},
		{"migrated", m.Migrated, m.Migrated == ""},
		{"salt", m.Salt, false},
		{"iterations", m.Iterations, m.Iterations == 0},
		{"master", m.Master, false},
		{"entries", m.Entries, false},
		{"sourceFile", m.SourceFile, m.SourceFile == ""},
		{"totalKeys", m.TotalKeys, false},
	}

	for _, field := range fields {
		if field.omit {
			delete(out, field.name)
			continue
		}
		if err := put(field.name, field.value); err != nil {
			return nil, err
		}
	}

	// entries must never marshal as null - it is a list, and an empty store has
	// an empty one.
	if m.Entries == nil {
		out["entries"] = json.RawMessage("[]")
	}

	return json.Marshal(out)
}

// format reports the store format a metadata document is in. Absent means 1.0,
// which is the same on-disk shape as 2.0 - 2.0 only added optional fields.
func (m metadata) format() string {
	if m.Version == "" {
		return "1.0"
	}
	return m.Version
}

// legacy reports whether this store predates format 3.0.
func (m metadata) legacy() bool {
	return majorOf(m.format()) < 3
}

// iterations reports the count this store was written with. Absent means it
// predates the field, and every version that did so used 100,000.
func (m metadata) iterations() int {
	if m.Iterations == 0 {
		return legacyIterations
	}
	return m.Iterations
}

// ivLen and bindsContext are the two things a store's format decides.
func (m metadata) ivLen() int {
	if m.legacy() {
		return ivLengthLegacy
	}
	return ivLength
}

func (m metadata) masterAAD() string {
	if m.legacy() {
		return ""
	}
	return contextMaster
}

func (m metadata) valueAAD(keyName string) string {
	if m.legacy() {
		return ""
	}
	return valueContext(keyName)
}

func majorOf(version string) int {
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}

// valueRecord is one .enc file.
type valueRecord struct {
	Salt string `json:"salt"`
	// Iterations only means anything to a 2.0 value, where the value key is
	// stretched from the master key. A 3.0 value derives with HKDF, which takes
	// no count, so the field is omitted rather than written as a number nothing
	// reads.
	Iterations int       `json:"iterations,omitempty"`
	Data       encrypted `json:"data"`
}

// StoreInfo is everything about a store that can be known without decrypting
// anything.
type StoreInfo struct {
	Name string
	Path string
	// Version is the store format, "3.0" for anything this build writes.
	Version string
	// Current is false if the store is still in format 2.0 and would benefit
	// from [Keystore.Migrate].
	Current    bool
	Created    string
	Updated    string
	Iterations int
	TotalKeys  int
	Keys       []string
	SourceFile string
}

// SecureResult is what [Keystore.Secure] returns.
type SecureResult struct {
	StoreName string
	StoreDir  string
	TotalKeys int
	Keys      []string
}

// SetResult is what [Keystore.Set] returns.
type SetResult struct {
	Key       string
	StoreName string
	// Added is true if the key was new, false if an existing value was replaced.
	Added bool
	// Format is the format the record was written in - a 2.0 store keeps taking
	// 2.0 writes.
	Format string
}

// MigrateResult is what [Keystore.Migrate] returns.
type MigrateResult struct {
	StoreName  string
	From       string
	To         string
	Keys       []string
	Iterations int
}

// Keystore is a secure key-value store backed by a directory.
//
// One instance binds one keystore directory and one set of options, validated
// once in [New] rather than on every call. It holds no secret of its own - the
// user key is passed to each operation that needs it and is never retained - so
// one instance built at start-up is safe to keep for the life of the process.
//
// It is safe for concurrent reads. Concurrent writes to the same store are not
// serialised by this package.
type Keystore struct {
	options Options
}

// New binds a set of options, validating them once rather than on every call.
func New(options ...Options) (*Keystore, error) {
	resolved, err := resolveOptions(options)
	if err != nil {
		return nil, err
	}

	if resolved.CreateDir {
		if err := os.MkdirAll(resolved.KeystoreDir, 0o700); err != nil {
			return nil, wrapf(CodeInvalidOptions, err, "could not create %s", resolved.KeystoreDir)
		}
	}

	return &Keystore{options: resolved}, nil
}

// Options returns the options this keystore was built with.
func (k *Keystore) Options() Options { return k.options }

// Dir returns the keystore directory.
func (k *Keystore) Dir() string { return k.options.KeystoreDir }

func (k *Keystore) log(format string, args ...any) {
	if k.options.Logger != nil {
		k.options.Logger(fmt.Sprintf(format, args...))
	}
}

func (k *Keystore) storeDir(storeName string) string {
	return filepath.Join(k.options.KeystoreDir, storeName)
}

// readMetadata reads and parses a store's master.json, or says which of the two
// is missing.
func (k *Keystore) readMetadata(storeName string) (*metadata, error) {
	dir := k.storeDir(storeName)

	if _, err := os.Stat(dir); err != nil {
		return nil, failf(CodeStoreNotFound, "keystore %q not found", storeName)
	}

	content, err := os.ReadFile(filepath.Join(dir, masterFile))
	if err != nil {
		return nil, failf(CodeStoreCorrupt,
			"keystore %q has no %s - the directory exists but is not a store", storeName, masterFile)
	}

	var meta metadata
	if err := json.Unmarshal(content, &meta); err != nil {
		return nil, wrapf(CodeStoreCorrupt, err, "%s in keystore %q is not readable JSON", masterFile, storeName)
	}

	if majorOf(meta.format()) > majorOf(StoreFormatVersion) {
		return nil, failf(CodeUnsupportedFormat,
			"keystore %q is in format %s, and this build reads up to %s",
			storeName, meta.format(), StoreFormatVersion)
	}

	return &meta, nil
}

func (k *Keystore) writeMetadata(storeName string, meta *metadata) error {
	meta.Updated = time.Now().UTC().Format(time.RFC3339Nano)

	encoded, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return wrapf(CodeStoreCorrupt, err, "could not serialise %s", masterFile)
	}

	return os.WriteFile(filepath.Join(k.storeDir(storeName), masterFile), encoded, 0o600)
}

// unlockMaster stretches the user key and decrypts the store's master key.
func (k *Keystore) unlockMaster(meta *metadata, userKey, storeName string) (string, error) {
	if userKey == "" {
		return "", failf(CodeInvalidArgument, "a userKey is required to read this store")
	}

	salt, err := hex.DecodeString(meta.Salt)
	if err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "keystore %q has a malformed salt", storeName)
	}

	userDerived, err := stretchPassword(userKey, salt, meta.iterations())
	if err != nil {
		return "", err
	}

	masterKey, err := decryptWith(meta.Master, meta.masterAAD(), userDerived, "master key")
	if err != nil {
		if CodeOf(err) == CodeBadUserKey {
			return "", &Error{
				Code:    CodeBadUserKey,
				Message: fmt.Sprintf("wrong user key for keystore %q", storeName),
				Cause:   err,
			}
		}
		return "", err
	}

	return masterKey, nil
}

// valueKey is the key one value is encrypted under.
//
// In 3.0 that is HKDF from the master key, with the value's salt and a context
// naming the key - so a value file moved to another key's name derives a
// different key entirely. In 2.0 it was PBKDF2 over the master key, at the
// store's full iteration count, with nothing binding it to the name.
func valueKey(masterKey string, salt []byte, keyName string, meta *metadata, record *valueRecord) ([]byte, error) {
	if meta.legacy() {
		count := record.Iterations
		if count == 0 {
			count = meta.iterations()
		}
		return stretchPassword(masterKey, salt, count)
	}
	return deriveFromKey(masterKey, salt, valueContext(keyName))
}

func (k *Keystore) readValue(storeName string, entry entryRef, masterKey string, meta *metadata) (string, error) {
	content, err := os.ReadFile(filepath.Join(k.storeDir(storeName), entry.File))
	if err != nil {
		return "", failf(CodeStoreCorrupt,
			"key %q is listed in %s but its file %s is missing", entry.Key, masterFile, entry.File)
	}

	var record valueRecord
	if err := json.Unmarshal(content, &record); err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "the file for key %q is not readable JSON", entry.Key)
	}

	salt, err := hex.DecodeString(record.Salt)
	if err != nil {
		return "", wrapf(CodeStoreCorrupt, err, "the file for key %q has a malformed salt", entry.Key)
	}

	key, err := valueKey(masterKey, salt, entry.Key, meta, &record)
	if err != nil {
		return "", err
	}

	return decryptWith(record.Data, meta.valueAAD(entry.Key), key, fmt.Sprintf("value for %q", entry.Key))
}

func (k *Keystore) writeValue(storeName, fileName, keyName, value, masterKey string, meta *metadata) error {
	salt, err := randomBytes(valueSaltLength)
	if err != nil {
		return err
	}

	record := valueRecord{Salt: hex.EncodeToString(salt)}
	if meta.legacy() {
		record.Iterations = meta.iterations()
	}

	key, err := valueKey(masterKey, salt, keyName, meta, &record)
	if err != nil {
		return err
	}

	record.Data, err = encryptWith(value, meta.valueAAD(keyName), key, meta.ivLen())
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return wrapf(CodeStoreCorrupt, err, "could not serialise the value for %q", keyName)
	}

	return os.WriteFile(filepath.Join(k.storeDir(storeName), fileName), encoded, 0o600)
}

// Secure encrypts a key-value file into a store, in format 3.0.
//
// The input format follows the extension: .json an object, .env dotenv lines,
// anything else key:value lines with master: first. An empty storeName defaults
// to the input file's base name.
//
// Re-securing an existing store replaces it. The old .enc files go first, so a
// key dropped from the input does not linger on disk as an encrypted orphan
// that nothing references any more.
func (k *Keystore) Secure(inputFile, userKey, storeName string) (*SecureResult, error) {
	if userKey == "" {
		return nil, failf(CodeInvalidArgument, "Secure requires a userKey")
	}

	masterKey, entries, err := ParseInput(inputFile)
	if err != nil {
		return nil, err
	}
	if masterKey == "" {
		return nil, failf(CodeBadInput,
			`input must define a master key (e.g. "master:..." in .txt, "master=..." in .env, `+
				`or a "master" property in .json)`)
	}
	if len(entries) == 0 {
		return nil, failf(CodeBadInput, "no key-value entries found in input file")
	}

	if storeName == "" {
		base := filepath.Base(inputFile)
		storeName = strings.TrimSuffix(base, filepath.Ext(base))
	}

	dir := k.storeDir(storeName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, wrapf(CodeStoreCorrupt, err, "could not create %s", dir)
	}

	existing, err := os.ReadDir(dir)
	if err == nil {
		for _, file := range existing {
			name := file.Name()
			if strings.HasSuffix(name, valueExtension) || name == masterFile {
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}

	storeSalt, err := randomBytes(storeSaltLength)
	if err != nil {
		return nil, err
	}

	userDerived, err := stretchPassword(userKey, storeSalt, k.options.Iterations)
	if err != nil {
		return nil, err
	}

	master, err := encryptWith(masterKey, contextMaster, userDerived, ivLength)
	if err != nil {
		return nil, err
	}

	meta := &metadata{
		Version:    StoreFormatVersion,
		Created:    time.Now().UTC().Format(time.RFC3339Nano),
		Salt:       hex.EncodeToString(storeSalt),
		Iterations: k.options.Iterations,
		Master:     master,
		Entries:    make([]entryRef, 0, len(entries)),
		SourceFile: filepath.Base(inputFile),
		TotalKeys:  len(entries),
		extra:      map[string]json.RawMessage{},
	}

	keys := make([]string, 0, len(entries))
	for _, entry := range entries {
		file := safeFileName(entry.Key)
		if err := k.writeValue(storeName, file, entry.Key, entry.Value, masterKey, meta); err != nil {
			return nil, err
		}
		meta.Entries = append(meta.Entries, entryRef{Key: entry.Key, File: file})
		keys = append(keys, entry.Key)
	}

	if err := k.writeMetadata(storeName, meta); err != nil {
		return nil, err
	}
	if err := k.updateIndex(storeName, meta); err != nil {
		return nil, err
	}

	k.log("Secured %d keys in keystore %q at %s", len(entries), storeName, dir)

	return &SecureResult{StoreName: storeName, StoreDir: dir, TotalKeys: len(entries), Keys: keys}, nil
}

// Get decrypts and returns one value.
//
// An empty storeName searches every store. That is a convenience for a
// single-store setup and a trap for a multi-store one, where two stores may
// hold the same key name and the first match wins - name the store when it
// matters.
func (k *Keystore) Get(key, userKey, storeName string) (string, error) {
	if storeName == "" {
		found, err := k.findStoreForKey(key)
		if err != nil {
			return "", err
		}
		storeName = found
	}

	meta, err := k.readMetadata(storeName)
	if err != nil {
		return "", err
	}

	index := -1
	for i, entry := range meta.Entries {
		if entry.Key == key {
			index = i
			break
		}
	}
	if index == -1 {
		return "", failf(CodeKeyNotFound, "key %q not found in keystore %q", key, storeName)
	}

	masterKey, err := k.unlockMaster(meta, userKey, storeName)
	if err != nil {
		return "", err
	}

	return k.readValue(storeName, meta.Entries[index], masterKey, meta)
}

// GetAll decrypts every value in a store.
//
// The user key is stretched once, not once per value, so this costs one PBKDF2
// derivation however many keys the store holds.
func (k *Keystore) GetAll(userKey, storeName string) (map[string]string, error) {
	meta, err := k.readMetadata(storeName)
	if err != nil {
		return nil, err
	}

	masterKey, err := k.unlockMaster(meta, userKey, storeName)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string, len(meta.Entries))
	for _, entry := range meta.Entries {
		value, err := k.readValue(storeName, entry, masterKey, meta)
		if err != nil {
			return nil, err
		}
		values[entry.Key] = value
	}

	return values, nil
}

// Set adds a key, or replaces the value of one already there.
//
// The replacement gets a fresh salt and a fresh IV, so an observer who kept the
// old file learns nothing by comparing it with the new one.
//
// On a store still in format 2.0 this writes a 2.0 record, so the store stays
// internally consistent. Run [Keystore.Migrate] to move the whole store to 3.0.
func (k *Keystore) Set(key, value, userKey, storeName string) (*SetResult, error) {
	if key == "" {
		return nil, failf(CodeInvalidArgument, "Set requires a key")
	}

	meta, err := k.readMetadata(storeName)
	if err != nil {
		return nil, err
	}

	masterKey, err := k.unlockMaster(meta, userKey, storeName)
	if err != nil {
		return nil, err
	}

	file := safeFileName(key)
	added := true
	for _, entry := range meta.Entries {
		if entry.Key == key {
			file = entry.File
			added = false
			break
		}
	}

	if err := k.writeValue(storeName, file, key, value, masterKey, meta); err != nil {
		return nil, err
	}

	if added {
		meta.Entries = append(meta.Entries, entryRef{Key: key, File: file})
		meta.TotalKeys = len(meta.Entries)
	}

	if err := k.writeMetadata(storeName, meta); err != nil {
		return nil, err
	}
	if err := k.updateIndex(storeName, meta); err != nil {
		return nil, err
	}

	verb := "updated"
	if added {
		verb = "added"
	}
	k.log("Key %q %s in keystore %q", key, verb, storeName)

	return &SetResult{Key: key, StoreName: storeName, Added: added, Format: meta.format()}, nil
}

// Migrate rewrites a whole store in the current format.
//
// Every value is decrypted with the old parameters and re-encrypted with the
// new ones, under a fresh store salt and fresh per-value salts. The master key
// itself does not change, so nothing outside the store has to be told.
//
// A store already on the current format is re-encrypted rather than skipped,
// which is what makes this the way to raise a store's iteration count as well
// as its format.
//
// The rewrite is not atomic. Every value is decrypted before anything is
// written, so a wrong user key changes nothing; and every new value file is
// written before master.json, so an interruption leaves the store readable in
// its old format. Export first anyway.
func (k *Keystore) Migrate(storeName, userKey string) (*MigrateResult, error) {
	meta, err := k.readMetadata(storeName)
	if err != nil {
		return nil, err
	}
	from := meta.format()

	masterKey, err := k.unlockMaster(meta, userKey, storeName)
	if err != nil {
		return nil, err
	}

	// Decrypt everything up front. If any value fails, the store is untouched.
	type pair struct{ key, value string }
	values := make([]pair, 0, len(meta.Entries))
	for _, entry := range meta.Entries {
		value, err := k.readValue(storeName, entry, masterKey, meta)
		if err != nil {
			return nil, err
		}
		values = append(values, pair{entry.Key, value})
	}

	storeSalt, err := randomBytes(storeSaltLength)
	if err != nil {
		return nil, err
	}

	userDerived, err := stretchPassword(userKey, storeSalt, k.options.Iterations)
	if err != nil {
		return nil, err
	}

	master, err := encryptWith(masterKey, contextMaster, userDerived, ivLength)
	if err != nil {
		return nil, err
	}

	rewritten := *meta
	rewritten.Version = StoreFormatVersion
	rewritten.Salt = hex.EncodeToString(storeSalt)
	rewritten.Iterations = k.options.Iterations
	rewritten.Master = master
	rewritten.Migrated = time.Now().UTC().Format(time.RFC3339Nano)
	rewritten.Entries = make([]entryRef, 0, len(values))
	rewritten.TotalKeys = len(values)

	dir := k.storeDir(storeName)
	stale := map[string]bool{}
	if existing, err := os.ReadDir(dir); err == nil {
		for _, file := range existing {
			if strings.HasSuffix(file.Name(), valueExtension) {
				stale[file.Name()] = true
			}
		}
	}

	keys := make([]string, 0, len(values))
	for _, item := range values {
		file := safeFileName(item.key)
		if err := k.writeValue(storeName, file, item.key, item.value, masterKey, &rewritten); err != nil {
			return nil, err
		}
		rewritten.Entries = append(rewritten.Entries, entryRef{Key: item.key, File: file})
		keys = append(keys, item.key)
		delete(stale, file)
	}

	if err := k.writeMetadata(storeName, &rewritten); err != nil {
		return nil, err
	}
	for file := range stale {
		_ = os.Remove(filepath.Join(dir, file))
	}

	if err := k.updateIndex(storeName, &rewritten); err != nil {
		return nil, err
	}

	if from == StoreFormatVersion {
		k.log("Keystore %q re-encrypted in format %s at %d iterations", storeName, StoreFormatVersion, k.options.Iterations)
	} else {
		k.log("Keystore %q migrated from format %s to %s", storeName, from, StoreFormatVersion)
	}

	return &MigrateResult{
		StoreName:  storeName,
		From:       from,
		To:         StoreFormatVersion,
		Keys:       keys,
		Iterations: k.options.Iterations,
	}, nil
}

// DeleteKey removes one key and its encrypted file.
func (k *Keystore) DeleteKey(key, storeName string) error {
	meta, err := k.readMetadata(storeName)
	if err != nil {
		return err
	}

	index := -1
	for i, entry := range meta.Entries {
		if entry.Key == key {
			index = i
			break
		}
	}
	if index == -1 {
		return failf(CodeKeyNotFound, "key %q not found in keystore %q", key, storeName)
	}

	removed := meta.Entries[index]
	meta.Entries = append(meta.Entries[:index], meta.Entries[index+1:]...)
	meta.TotalKeys = len(meta.Entries)

	_ = os.Remove(filepath.Join(k.storeDir(storeName), removed.File))

	if err := k.writeMetadata(storeName, meta); err != nil {
		return err
	}
	if err := k.updateIndex(storeName, meta); err != nil {
		return err
	}

	k.log("Key %q deleted from keystore %q", key, storeName)
	return nil
}

// ListStores returns the names of every store under this keystore directory.
//
// A directory counts as a store only if it holds a master.json, so an unrelated
// directory sitting alongside is not reported as one.
func (k *Keystore) ListStores() ([]string, error) {
	files, err := os.ReadDir(k.options.KeystoreDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, wrapf(CodeStoreCorrupt, err, "could not read %s", k.options.KeystoreDir)
	}

	stores := []string{}
	for _, file := range files {
		if !file.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(k.options.KeystoreDir, file.Name(), masterFile)); err == nil {
			stores = append(stores, file.Name())
		}
	}

	return stores, nil
}

// ListKeys returns the key names in a store.
//
// No user key, and none is needed: names live in metadata in the clear. That is
// a deliberate trade - it is what makes listing useful without a password - and
// it means a key name must not itself be a secret.
func (k *Keystore) ListKeys(storeName string) ([]string, error) {
	meta, err := k.readMetadata(storeName)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(meta.Entries))
	for _, entry := range meta.Entries {
		keys = append(keys, entry.Key)
	}
	return keys, nil
}

// StoreInfo returns everything about a store that can be known without
// decrypting anything.
func (k *Keystore) StoreInfo(storeName string) (*StoreInfo, error) {
	meta, err := k.readMetadata(storeName)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(meta.Entries))
	for _, entry := range meta.Entries {
		keys = append(keys, entry.Key)
	}

	updated := meta.Updated
	if updated == "" {
		updated = meta.Created
	}

	return &StoreInfo{
		Name:       storeName,
		Path:       k.storeDir(storeName),
		Version:    meta.format(),
		Current:    !meta.legacy(),
		Created:    meta.Created,
		Updated:    updated,
		Iterations: meta.iterations(),
		TotalKeys:  meta.TotalKeys,
		Keys:       keys,
		SourceFile: meta.SourceFile,
	}, nil
}

// ExportStore writes a store to a single portable bundle, .skb by default.
//
// The contents are already encrypted, so the bundle is safe to move through a
// CI artifact store or an scp. An empty backupPath writes into the working
// directory under a stamped name.
func (k *Keystore) ExportStore(storeName, backupPath string) (string, error) {
	if _, err := k.readMetadata(storeName); err != nil {
		return "", err // refuse early if it is not a store
	}

	if backupPath == "" {
		stamp := time.Now().UnixMilli()
		backupPath = fmt.Sprintf("%s-backup-%d%s", storeName, stamp, DefaultBackupExtension)
	}

	bundle, err := buildBundle(k.storeDir(storeName), storeName)
	if err != nil {
		return "", err
	}

	encoded, err := json.Marshal(bundle)
	if err != nil {
		return "", wrapf(CodeBadBackup, err, "could not serialise the bundle")
	}
	if err := os.WriteFile(backupPath, encoded, 0o600); err != nil {
		return "", wrapf(CodeBadBackup, err, "could not write %s", backupPath)
	}

	k.log("Store %q exported to %s", storeName, backupPath)
	return backupPath, nil
}

// ImportStore restores a bundle, under its own name or a new one. An empty
// storeName uses the name the bundle carries.
func (k *Keystore) ImportStore(backupPath, storeName string) (string, error) {
	bundle, err := readBundle(backupPath)
	if err != nil {
		return "", err
	}

	target := storeName
	if target == "" {
		target = bundle.StoreName
	}
	if target == "" {
		return "", failf(CodeBadBackup,
			"cannot determine a target store name: the bundle names none and none was given")
	}

	if err := writeBundle(bundle, k.storeDir(target)); err != nil {
		return "", err
	}

	meta, err := k.readMetadata(target)
	if err != nil {
		return "", err
	}
	if err := k.updateIndex(target, meta); err != nil {
		return "", err
	}

	k.log("Store imported as %q", target)
	return target, nil
}

// DeleteStore removes a store and its index entry. There is no undo; export
// first.
func (k *Keystore) DeleteStore(storeName string) error {
	if _, err := k.readMetadata(storeName); err != nil {
		return err // refuse to delete a directory that is not a store
	}

	if err := os.RemoveAll(k.storeDir(storeName)); err != nil {
		return wrapf(CodeStoreCorrupt, err, "could not remove %s", k.storeDir(storeName))
	}

	indexPath := filepath.Join(k.options.KeystoreDir, indexFile)
	if content, err := os.ReadFile(indexPath); err == nil {
		var catalogue struct {
			Stores  map[string]json.RawMessage `json:"stores"`
			Updated string                     `json:"updated"`
		}
		if json.Unmarshal(content, &catalogue) == nil && catalogue.Stores != nil {
			delete(catalogue.Stores, storeName)
			catalogue.Updated = time.Now().UTC().Format(time.RFC3339Nano)
			if encoded, err := json.MarshalIndent(catalogue, "", "  "); err == nil {
				_ = os.WriteFile(indexPath, encoded, 0o600)
			}
		}
	}

	k.log("Keystore %q deleted", storeName)
	return nil
}

// EncryptValue is instance sugar for the package-level [EncryptValue].
func (k *Keystore) EncryptValue(plaintext, userKey string, options ...TokenOptions) (string, error) {
	return EncryptValue(plaintext, userKey, options...)
}

// DecryptValue is instance sugar for the package-level [DecryptValue].
func (k *Keystore) DecryptValue(token, userKey string) (string, error) {
	return DecryptValue(token, userKey)
}

// updateIndex rewrites this store's entry in the keystore-wide catalogue.
//
// The catalogue holds names and counts and no secrets, which is what makes it
// safe to read without a user key - and what makes it merely a convenience:
// every operation reads the store's own master.json for anything that matters.
func (k *Keystore) updateIndex(storeName string, meta *metadata) error {
	indexPath := filepath.Join(k.options.KeystoreDir, indexFile)

	catalogue := struct {
		Stores  map[string]any `json:"stores"`
		Updated string         `json:"updated"`
	}{Stores: map[string]any{}}

	if content, err := os.ReadFile(indexPath); err == nil {
		// A corrupt catalogue is not worth failing a write over - it holds
		// nothing that is not also in each store's own metadata. Rebuild it.
		if json.Unmarshal(content, &catalogue) != nil || catalogue.Stores == nil {
			catalogue.Stores = map[string]any{}
		}
	}

	keys := make([]string, 0, len(meta.Entries))
	for _, entry := range meta.Entries {
		keys = append(keys, entry.Key)
	}

	catalogue.Stores[storeName] = map[string]any{
		"version":    meta.format(),
		"created":    meta.Created,
		"totalKeys":  meta.TotalKeys,
		"keys":       keys,
		"sourceFile": meta.SourceFile,
	}
	catalogue.Updated = time.Now().UTC().Format(time.RFC3339Nano)

	encoded, err := json.MarshalIndent(catalogue, "", "  ")
	if err != nil {
		return wrapf(CodeStoreCorrupt, err, "could not serialise %s", indexFile)
	}

	return os.WriteFile(indexPath, encoded, 0o600)
}

// findStoreForKey returns the first store holding this key.
func (k *Keystore) findStoreForKey(key string) (string, error) {
	stores, err := k.ListStores()
	if err != nil {
		return "", err
	}

	for _, storeName := range stores {
		keys, err := k.ListKeys(storeName)
		if err != nil {
			continue // a store we cannot read is not a store that holds the key
		}
		for _, candidate := range keys {
			if candidate == key {
				return storeName, nil
			}
		}
	}

	return "", failf(CodeKeyNotFound, "key %q not found in any keystore", key)
}
