package securekeystore_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	ks "github.com/eharain/secure-keystore/go"
)

// The shared corpus, run against this implementation.
//
// The corpus was written by the JavaScript encoder. Nothing here has ever seen
// that code - this package was written against SPEC.md - so passing this file
// is the whole cross-language claim, tested rather than asserted.
//
// It cannot be a comparison of encoders: every write in this format draws a
// fresh salt and a fresh IV, so two implementations encrypting the same secret
// never produce the same bytes. What is pinned is the other direction - these
// bytes, under this key, must come back as this plaintext - plus the refusals,
// which matter just as much. An implementation that accepts a tampered token is
// not conforming however well it handles the happy path.

type manifest struct {
	UserKey    string `json:"userKey"`
	MasterKey  string `json:"masterKey"`
	Iterations int    `json:"iterations"`

	Stores []struct {
		Name         string            `json:"name"`
		KeystorePath string            `json:"keystorePath"`
		Format       string            `json:"format"`
		Note         string            `json:"note"`
		Expected     map[string]string `json:"expected"`
	} `json:"stores"`

	Tokens []struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Token    string `json:"token"`
		Expected string `json:"expected"`
	} `json:"tokens"`

	Bundles []struct {
		Name                  string            `json:"name"`
		Path                  string            `json:"path"`
		ImportAs              string            `json:"importAs"`
		Expected              map[string]string `json:"expected"`
		MustNotCreate         []string          `json:"mustNotCreate"`
		MustCreateInsideStore []string          `json:"mustCreateInsideStore"`
	} `json:"bundles"`

	Refusals struct {
		Tokens []struct {
			Name    string `json:"name"`
			Token   string `json:"token"`
			UserKey string `json:"userKey"`
			Code    string `json:"code"`
		} `json:"tokens"`
		Bundles []struct {
			Name string `json:"name"`
			Path string `json:"path"`
			Code string `json:"code"`
			Note string `json:"note"`
		} `json:"bundles"`
		Stores []struct {
			Name         string `json:"name"`
			KeystorePath string `json:"keystorePath"`
			Store        string `json:"store"`
			Code         string `json:"code"`
			Note         string `json:"note"`
		} `json:"stores"`
	} `json:"refusals"`
}

const corpusDir = "../conformance"

func loadManifest(t *testing.T) *manifest {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(corpusDir, "manifest.json"))
	if err != nil {
		t.Skipf("no conformance corpus (%v) - run: node conformance/generate.js", err)
	}

	var loaded manifest
	if err := json.Unmarshal(content, &loaded); err != nil {
		t.Fatalf("corpus manifest is not readable: %v", err)
	}
	return &loaded
}

func fixture(relative string) string {
	return filepath.Join(corpusDir, "fixtures", filepath.FromSlash(relative))
}

// reader opens a corpus keystore without creating anything.
func reader(t *testing.T, keystorePath string) *ks.Keystore {
	t.Helper()

	options := ks.DefaultOptions()
	options.KeystoreDir = fixture(keystorePath)
	options.CreateDir = false

	store, err := ks.New(options)
	if err != nil {
		t.Fatalf("could not open %s: %v", keystorePath, err)
	}
	return store
}

func TestConformanceStores(t *testing.T) {
	m := loadManifest(t)

	for _, store := range m.Stores {
		t.Run(store.Name, func(t *testing.T) {
			keystore := reader(t, store.KeystorePath)

			info, err := keystore.StoreInfo(store.Name)
			if err != nil {
				t.Fatalf("StoreInfo: %v", err)
			}
			if info.Version != store.Format {
				t.Errorf("format = %q, want %q", info.Version, store.Format)
			}

			values, err := keystore.GetAll(m.UserKey, store.Name)
			if err != nil {
				t.Fatalf("GetAll: %v", err)
			}
			if len(values) != len(store.Expected) {
				t.Errorf("got %d values, want %d", len(values), len(store.Expected))
			}
			for key, want := range store.Expected {
				if got := values[key]; got != want {
					t.Errorf("GetAll[%q] = %q, want %q", key, got, want)
				}
			}

			// And one at a time, which takes a different path through the code.
			for key, want := range store.Expected {
				got, err := keystore.Get(key, m.UserKey, store.Name)
				if err != nil {
					t.Errorf("Get(%q): %v", key, err)
					continue
				}
				if got != want {
					t.Errorf("Get(%q) = %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestConformanceTokens(t *testing.T) {
	m := loadManifest(t)

	for _, token := range m.Tokens {
		t.Run(token.Name, func(t *testing.T) {
			got, err := ks.DecryptValue(token.Token, m.UserKey)
			if err != nil {
				t.Fatalf("DecryptValue: %v", err)
			}
			if got != token.Expected {
				t.Errorf("= %q, want %q", got, token.Expected)
			}

			if token.Version == "" {
				if ks.IsEncryptedValue(token.Token) {
					t.Errorf("%q is not a token but was recognised as one", token.Token)
				}
				return
			}
			if !ks.IsEncryptedValue(token.Token) {
				t.Errorf("%q is a token but was not recognised as one", token.Token)
			}
			if got := ks.TokenVersion(token.Token); got != token.Version {
				t.Errorf("TokenVersion = %q, want %q", got, token.Version)
			}
		})
	}
}

func TestConformanceBundles(t *testing.T) {
	m := loadManifest(t)

	for _, bundle := range m.Bundles {
		t.Run(bundle.Name, func(t *testing.T) {
			dir := t.TempDir()

			options := ks.DefaultOptions()
			options.KeystoreDir = filepath.Join(dir, ".keystore")
			keystore, err := ks.New(options)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			imported, err := keystore.ImportStore(fixture(bundle.Path), bundle.ImportAs)
			if err != nil {
				t.Fatalf("ImportStore: %v", err)
			}
			if imported != bundle.ImportAs {
				t.Errorf("imported as %q, want %q", imported, bundle.ImportAs)
			}

			values, err := keystore.GetAll(m.UserKey, bundle.ImportAs)
			if err != nil {
				t.Fatalf("GetAll: %v", err)
			}
			for key, want := range bundle.Expected {
				if got := values[key]; got != want {
					t.Errorf("[%q] = %q, want %q", key, got, want)
				}
			}

			// A hostile bundle must land entirely inside the target store.
			for _, name := range bundle.MustNotCreate {
				for _, outside := range []string{
					filepath.Join(dir, name),
					filepath.Join(dir, ".keystore", name),
				} {
					if _, err := os.Stat(outside); err == nil {
						t.Errorf("bundle escaped: %s exists", outside)
					}
				}
			}
			for _, name := range bundle.MustCreateInsideStore {
				inside := filepath.Join(dir, ".keystore", bundle.ImportAs, name)
				if _, err := os.Stat(inside); err != nil {
					t.Errorf("expected %s inside the store: %v", name, err)
				}
			}
		})
	}
}

func TestConformanceTokenRefusals(t *testing.T) {
	m := loadManifest(t)

	for _, refusal := range m.Refusals.Tokens {
		t.Run(refusal.Name, func(t *testing.T) {
			got, err := ks.DecryptValue(refusal.Token, refusal.UserKey)
			if err == nil {
				t.Fatalf("expected a refusal, got %q", got)
			}
			if code := string(ks.CodeOf(err)); code != refusal.Code {
				t.Errorf("code = %q, want %q (%v)", code, refusal.Code, err)
			}
		})
	}
}

func TestConformanceBundleRefusals(t *testing.T) {
	m := loadManifest(t)

	for _, refusal := range m.Refusals.Bundles {
		t.Run(refusal.Name, func(t *testing.T) {
			dir := t.TempDir()

			options := ks.DefaultOptions()
			options.KeystoreDir = filepath.Join(dir, ".keystore")
			keystore, err := ks.New(options)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			if _, err := keystore.ImportStore(fixture(refusal.Path), "target"); err == nil {
				t.Fatalf("expected a refusal (%s)", refusal.Note)
			} else if code := string(ks.CodeOf(err)); code != refusal.Code {
				t.Errorf("code = %q, want %q (%v)", code, refusal.Code, err)
			}
		})
	}
}

func TestConformanceStoreRefusals(t *testing.T) {
	m := loadManifest(t)

	for _, refusal := range m.Refusals.Stores {
		t.Run(refusal.Name, func(t *testing.T) {
			keystore := reader(t, refusal.KeystorePath)

			if _, err := keystore.StoreInfo(refusal.Store); err == nil {
				t.Fatalf("expected a refusal (%s)", refusal.Note)
			} else if code := string(ks.CodeOf(err)); code != refusal.Code {
				t.Errorf("code = %q, want %q (%v)", code, refusal.Code, err)
			}
		})
	}
}

// TestConformanceCrossWrite is the other direction: a store this package wrote,
// read back through the corpus's own expectations. The JavaScript suite does
// the same against a store Go wrote, which is what closes the loop.
func TestConformanceCrossWrite(t *testing.T) {
	m := loadManifest(t)
	dir := t.TempDir()

	options := ks.DefaultOptions()
	options.KeystoreDir = filepath.Join(dir, ".keystore")
	options.Iterations = m.Iterations

	keystore, err := ks.New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Take the awkward values straight out of the corpus, so the two
	// implementations are exercising the same edge cases.
	var expected map[string]string
	for _, store := range m.Stores {
		if store.Name == "basic" {
			expected = store.Expected
			break
		}
	}
	if expected == nil {
		t.Skip("no 'basic' store in the corpus")
	}

	input := filepath.Join(dir, "go-written.env")
	if err := os.WriteFile(input, []byte("master="+m.MasterKey+"\nplaceholder=x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := keystore.Secure(input, m.UserKey, "go-written"); err != nil {
		t.Fatalf("Secure: %v", err)
	}

	for key, value := range expected {
		if _, err := keystore.Set(key, value, m.UserKey, "go-written"); err != nil {
			t.Fatalf("Set(%q): %v", key, err)
		}
	}
	if err := keystore.DeleteKey("placeholder", "go-written"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	values, err := keystore.GetAll(m.UserKey, "go-written")
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	for key, want := range expected {
		if got := values[key]; got != want {
			t.Errorf("[%q] = %q, want %q", key, got, want)
		}
	}

	// Leave it where the JavaScript suite can find it, if asked to.
	if out := os.Getenv("SECURE_KEYSTORE_CROSS_WRITE_DIR"); out != "" {
		if _, err := keystore.ExportStore("go-written", filepath.Join(out, "go-written.skb")); err != nil {
			t.Fatalf("ExportStore: %v", err)
		}
	}
}
