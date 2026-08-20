package securekeystore_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ks "github.com/eharain/secure-keystore/go"
)

// Tests written against the behaviour, not against the JavaScript. Where a
// property is shared across implementations it is in the corpus instead; this
// file is what is specific to Go, plus the things worth asserting twice.

// fast is the floor. The real default is 600,000, which is the point of it and
// which would make this file take a minute.
const fast = ks.MinIterations

const (
	userKey   = "testUser123!@#"
	masterKey = "TestMasterKey123"
)

var keysTxt = strings.Join([]string{
	"master:" + masterKey,
	"api_key:sk_test_abc123",
	"jwt_secret:test_secret_xyz",
	"db_url:postgres://user:pass@host:5432/db",
}, "\n")

func newStore(t *testing.T, iterations int) (*ks.Keystore, string) {
	t.Helper()

	dir := t.TempDir()
	options := ks.DefaultOptions()
	options.KeystoreDir = filepath.Join(dir, ".keystore")
	options.Iterations = iterations

	store, err := ks.New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, dir
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecureThenGet(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	result, err := store.Secure(input, userKey, "prod")
	if err != nil {
		t.Fatalf("Secure: %v", err)
	}
	if result.TotalKeys != 3 {
		t.Errorf("TotalKeys = %d, want 3", result.TotalKeys)
	}

	got, err := store.Get("api_key", userKey, "prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "sk_test_abc123" {
		t.Errorf("= %q, want %q", got, "sk_test_abc123")
	}

	// Only the first colon splits, so the URL survives intact.
	url, err := store.Get("db_url", userKey, "prod")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if url != "postgres://user:pass@host:5432/db" {
		t.Errorf("db_url = %q", url)
	}
}

func TestStoreNameDefaultsToFileName(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "staging.txt", keysTxt)

	result, err := store.Secure(input, userKey, "")
	if err != nil {
		t.Fatalf("Secure: %v", err)
	}
	if result.StoreName != "staging" {
		t.Errorf("StoreName = %q, want %q", result.StoreName, "staging")
	}
}

func TestWrongUserKeyIsReportedAsSuch(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	_, err := store.Get("api_key", "wrong-key", "prod")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, ks.ErrBadUserKey) {
		t.Errorf("errors.Is(err, ErrBadUserKey) = false, err = %v", err)
	}
	if ks.CodeOf(err) != ks.CodeBadUserKey {
		t.Errorf("CodeOf = %q", ks.CodeOf(err))
	}
	if !strings.Contains(err.Error(), `keystore "prod"`) {
		t.Errorf("message does not name the store: %v", err)
	}
}

func TestValueIsBoundToItsKeyName(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", "master:M\nfirst:VALUE_A\nsecond:VALUE_B")

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	// The format 2.0 gap, closed. On 2.0 both reads succeeded and returned each
	// other's values.
	storeDir := filepath.Join(store.Dir(), "prod")
	content, err := os.ReadFile(filepath.Join(storeDir, "master.json"))
	if err != nil {
		t.Fatal(err)
	}

	var meta struct {
		Entries []struct{ Key, File string } `json:"entries"`
	}
	if err := json.Unmarshal(content, &meta); err != nil {
		t.Fatal(err)
	}

	fileFor := func(key string) string {
		for _, entry := range meta.Entries {
			if entry.Key == key {
				return filepath.Join(storeDir, entry.File)
			}
		}
		t.Fatalf("no entry for %q", key)
		return ""
	}

	a, _ := os.ReadFile(fileFor("first"))
	b, _ := os.ReadFile(fileFor("second"))
	_ = os.WriteFile(fileFor("first"), b, 0o600)
	_ = os.WriteFile(fileFor("second"), a, 0o600)

	for _, key := range []string{"first", "second"} {
		if _, err := store.Get(key, userKey, "prod"); !errors.Is(err, ks.ErrBadUserKey) {
			t.Errorf("swapping %q should have been refused, got %v", key, err)
		}
	}
}

func TestTwelveByteIV(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	// 12 bytes is 24 hex characters. It is what cipher.NewGCM produces without
	// argument, and the only length .NET's AesGcm accepts at all.
	content, _ := os.ReadFile(filepath.Join(store.Dir(), "prod", "master.json"))

	var meta struct {
		Master struct{ IV, AuthTag string } `json:"master"`
	}
	if err := json.Unmarshal(content, &meta); err != nil {
		t.Fatal(err)
	}
	if len(meta.Master.IV) != 24 {
		t.Errorf("master IV is %d hex characters, want 24", len(meta.Master.IV))
	}
	if len(meta.Master.AuthTag) != 32 {
		t.Errorf("auth tag is %d hex characters, want 32", len(meta.Master.AuthTag))
	}
}

func TestSetAddsAndReplaces(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	added, err := store.Set("new_key", "new_value", userKey, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if !added.Added {
		t.Error("Added = false, want true")
	}
	if added.Format != ks.StoreFormatVersion {
		t.Errorf("Format = %q, want %q", added.Format, ks.StoreFormatVersion)
	}

	replaced, err := store.Set("api_key", "rotated", userKey, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Added {
		t.Error("Added = true, want false")
	}

	got, _ := store.Get("api_key", userKey, "prod")
	if got != "rotated" {
		t.Errorf("= %q, want %q", got, "rotated")
	}

	keys, _ := store.ListKeys("prod")
	if len(keys) != 4 {
		t.Errorf("%d keys, want 4: %v", len(keys), keys)
	}
}

func TestGetAllAndMigrate(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	before, err := store.GetAll(userKey, "prod")
	if err != nil {
		t.Fatal(err)
	}

	result, err := store.Migrate("prod", userKey)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if result.From != ks.StoreFormatVersion || result.To != ks.StoreFormatVersion {
		t.Errorf("migrated %s -> %s", result.From, result.To)
	}

	after, err := store.GetAll(userKey, "prod")
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range before {
		if after[key] != want {
			t.Errorf("[%q] = %q after migrate, want %q", key, after[key], want)
		}
	}
}

func TestMigrateLeavesStoreUntouchedOnWrongKey(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	masterPath := filepath.Join(store.Dir(), "prod", "master.json")
	before, _ := os.ReadFile(masterPath)

	if _, err := store.Migrate("prod", "wrong-key"); !errors.Is(err, ks.ErrBadUserKey) {
		t.Fatalf("expected ErrBadUserKey, got %v", err)
	}

	after, _ := os.ReadFile(masterPath)
	if string(before) != string(after) {
		t.Error("a failed migrate rewrote master.json")
	}
	if _, err := store.Get("api_key", userKey, "prod"); err != nil {
		t.Errorf("store no longer readable: %v", err)
	}
}

func TestKeyNameCannotEscapeTheStore(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	evil := "../../escape:key"
	if _, err := store.Set(evil, "evil_value", userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get(evil, userKey, "prod")
	if err != nil || got != "evil_value" {
		t.Errorf("round trip failed: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "escape:key")); err == nil {
		t.Error("the key name escaped the store directory")
	}

	// Two names that sanitise alike must still get separate files.
	if _, err := store.Set("a/b", "first", userKey, "prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set("a_b", "second", userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	first, _ := store.Get("a/b", userKey, "prod")
	second, _ := store.Get("a_b", userKey, "prod")
	if first != "first" || second != "second" {
		t.Errorf("collision: a/b = %q, a_b = %q", first, second)
	}
}

func TestListStoresIgnoresNonStores(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(store.Dir(), "not-a-store"), 0o700); err != nil {
		t.Fatal(err)
	}

	stores, err := store.ListStores()
	if err != nil {
		t.Fatal(err)
	}
	if len(stores) != 1 || stores[0] != "prod" {
		t.Errorf("ListStores = %v, want [prod]", stores)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	bundle, err := store.ExportStore("prod", filepath.Join(dir, "prod.skb"))
	if err != nil {
		t.Fatalf("ExportStore: %v", err)
	}

	imported, err := store.ImportStore(bundle, "restored")
	if err != nil {
		t.Fatalf("ImportStore: %v", err)
	}
	if imported != "restored" {
		t.Errorf("imported as %q", imported)
	}

	got, _ := store.Get("api_key", userKey, "restored")
	if got != "sk_test_abc123" {
		t.Errorf("= %q", got)
	}
}

func TestDeleteStoreRefusesANonStore(t *testing.T) {
	store, _ := newStore(t, fast)

	stranger := filepath.Join(store.Dir(), "important-data")
	if err := os.MkdirAll(stranger, 0o700); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(stranger, "notes.txt")
	if err := os.WriteFile(notes, []byte("do not delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteStore("important-data"); !errors.Is(err, ks.ErrStoreCorrupt) {
		t.Errorf("expected ErrStoreCorrupt, got %v", err)
	}
	if _, err := os.Stat(notes); err != nil {
		t.Error("it deleted the directory anyway")
	}
}

func TestUnknownFieldsSurviveARewrite(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	// A field a newer implementation added. Writing to the store must not drop
	// it - an older reader that silently downgrades a store is worse than one
	// that refuses it.
	masterPath := filepath.Join(store.Dir(), "prod", "master.json")
	content, _ := os.ReadFile(masterPath)

	var raw map[string]any
	if err := json.Unmarshal(content, &raw); err != nil {
		t.Fatal(err)
	}
	raw["somethingNewer"] = map[string]any{"a": 1}

	updated, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(masterPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Set("another", "value", userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	after, _ := os.ReadFile(masterPath)
	var reread map[string]any
	if err := json.Unmarshal(after, &reread); err != nil {
		t.Fatal(err)
	}
	if _, ok := reread["somethingNewer"]; !ok {
		t.Error("an unknown field was dropped on rewrite")
	}
}

func TestOptionsAreValidatedAtConstruction(t *testing.T) {
	options := ks.DefaultOptions()
	options.Iterations = 10

	if _, err := ks.New(options); !errors.Is(err, ks.ErrInvalidOptions) {
		t.Errorf("expected ErrInvalidOptions, got %v", err)
	}

	options = ks.DefaultOptions()
	options.KeystoreDir = ""
	if _, err := ks.New(options); !errors.Is(err, ks.ErrInvalidOptions) {
		t.Errorf("expected ErrInvalidOptions, got %v", err)
	}
}

func TestPackageIsSilentWithoutALogger(t *testing.T) {
	store, dir := newStore(t, fast)
	input := writeFile(t, dir, "keys.txt", keysTxt)

	// The default store has no logger. Nothing it does may print.
	if _, err := store.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}

	var lines []string
	options := ks.DefaultOptions()
	options.KeystoreDir = filepath.Join(dir, ".keystore-2")
	options.Iterations = fast
	options.Logger = func(message string) { lines = append(lines, message) }

	talkative, err := ks.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := talkative.Secure(input, userKey, "prod"); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "Secured 3 keys") {
		t.Errorf("logger got %v", lines)
	}
}

func TestTokenRoundTrip(t *testing.T) {
	token, err := ks.EncryptValue("sk_live_abc123", userKey, ks.TokenOptions{Iterations: fast})
	if err != nil {
		t.Fatal(err)
	}

	if got := ks.TokenVersion(token); got != "skv2" {
		t.Errorf("TokenVersion = %q", got)
	}
	if parts := strings.Split(token, ":"); len(parts) != 6 {
		t.Errorf("%d fields, want 6", len(parts))
	}

	back, err := ks.DecryptValue(token, userKey)
	if err != nil {
		t.Fatal(err)
	}
	if back != "sk_live_abc123" {
		t.Errorf("= %q", back)
	}

	// The empty string passes through, matching every other implementation.
	if got, _ := ks.EncryptValue("", userKey); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got, _ := ks.DecryptValue("not encrypted", userKey); got != "not encrypted" {
		t.Errorf("passthrough = %q", got)
	}
}

func TestParseTextFormats(t *testing.T) {
	master, entries, err := ks.ParseText("# comment\nmaster=M\nexport api=a\njwt=\"quoted\"\nno_equals", ks.FormatEnv)
	if err != nil {
		t.Fatal(err)
	}
	if master != "M" || len(entries) != 2 {
		t.Fatalf("master = %q, entries = %v", master, entries)
	}
	if entries[0] != (ks.Entry{Key: "api", Value: "a"}) || entries[1] != (ks.Entry{Key: "jwt", Value: "quoted"}) {
		t.Errorf("entries = %v", entries)
	}

	master, entries, err = ks.ParseText(`{"master":"M","api":"a","port":8080,"on":true}`, ks.FormatJSON)
	if err != nil {
		t.Fatal(err)
	}
	if master != "M" || len(entries) != 3 {
		t.Fatalf("master = %q, entries = %v", master, entries)
	}
	// Order is the document's order, and non-strings keep their JSON form.
	if entries[1].Key != "port" || entries[1].Value != "8080" {
		t.Errorf("entries[1] = %v", entries[1])
	}
	if entries[2].Value != "true" {
		t.Errorf("entries[2] = %v", entries[2])
	}

	if _, _, err := ks.ParseText("api:a\nmaster:M", ks.FormatColon); !errors.Is(err, ks.ErrBadInput) {
		t.Errorf("expected ErrBadInput, got %v", err)
	}
	if _, _, err := ks.ParseText("[1,2]", ks.FormatJSON); !errors.Is(err, ks.ErrBadInput) {
		t.Errorf("expected ErrBadInput for an array, got %v", err)
	}
}

func TestFormatFor(t *testing.T) {
	cases := map[string]ks.InputFormat{
		"keys.json": ks.FormatJSON,
		"KEYS.JSON": ks.FormatJSON,
		"keys.env":  ks.FormatEnv,
		"keys.txt":  ks.FormatColon,
		"keys":      ks.FormatColon,
	}
	for name, want := range cases {
		if got := ks.FormatFor(name); got != want {
			t.Errorf("FormatFor(%q) = %q, want %q", name, got, want)
		}
	}
}
