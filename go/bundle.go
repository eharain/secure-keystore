package securekeystore

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Export and import, as one JSON bundle.
//
// The contents are already encrypted, so a bundle is safe to put through a CI
// artifact store or an scp, and useless to anyone who intercepts it without the
// user key. It is pure JSON - no tar, no shell - so it behaves the same on every
// platform.

// Bundle is a whole store as one portable document.
type Bundle struct {
	Format    string            `json:"format"`
	Version   int               `json:"version"`
	StoreName string            `json:"storeName"`
	Files     map[string]string `json:"files"`
}

// buildBundle reads every file in a store directory into a bundle.
func buildBundle(storeDir, storeName string) (*Bundle, error) {
	names, err := os.ReadDir(storeDir)
	if err != nil {
		return nil, wrapf(CodeStoreNotFound, err, "could not read store directory %s", storeDir)
	}

	bundle := &Bundle{
		Format:    BackupFormat,
		Version:   BackupVersion,
		StoreName: storeName,
		Files:     make(map[string]string, len(names)),
	}

	for _, name := range names {
		if name.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(storeDir, name.Name()))
		if err != nil {
			return nil, wrapf(CodeStoreCorrupt, err, "could not read %s", name.Name())
		}
		bundle.Files[name.Name()] = string(content)
	}

	return bundle, nil
}

// readBundle reads a bundle off disk and checks it is one of ours before any of
// it is believed.
//
// The checks are in the order that matters: a file that is not JSON, a JSON
// document that is not a bundle, a bundle from a future version, and a bundle
// with no master.json are four different mistakes and each says so.
func readBundle(backupPath string) (*Bundle, error) {
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, wrapf(CodeBadBackup, err, "backup file not found: %s", backupPath)
	}

	var bundle Bundle
	if err := json.Unmarshal(content, &bundle); err != nil {
		return nil, wrapf(CodeBadBackup, err, "invalid backup file: %s is not readable as JSON", backupPath)
	}

	if bundle.Format != BackupFormat || bundle.Files == nil {
		return nil, failf(CodeBadBackup, "invalid backup file: %s is not a keystore bundle", backupPath)
	}
	if bundle.Version > BackupVersion {
		return nil, failf(CodeUnsupportedFormat,
			"backup was written in bundle format %d, and this build reads up to %d", bundle.Version, BackupVersion)
	}
	if _, ok := bundle.Files[masterFile]; !ok {
		return nil, failf(CodeBadBackup, "invalid backup: %s not found in bundle", masterFile)
	}

	return &bundle, nil
}

// writeBundle writes a bundle's files into a target directory.
//
// Every name is reduced to its base name first. A bundle is an untrusted file
// that arrived over a wire, and {"files": {"../../.ssh/authorized_keys": "..."}}
// is a bundle someone could write by hand.
//
// filepath.Base is not enough on its own for a Windows path arriving in a
// bundle written on Unix, or the reverse, so the separator is normalised first.
func writeBundle(bundle *Bundle, targetDir string) error {
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		return wrapf(CodeBadBackup, err, "could not create %s", targetDir)
	}

	for name, content := range bundle.Files {
		safe := baseName(name)
		if safe == "" || safe == "." || safe == ".." {
			continue
		}
		if err := os.WriteFile(filepath.Join(targetDir, safe), []byte(content), 0o600); err != nil {
			return wrapf(CodeBadBackup, err, "could not write %s", safe)
		}
	}

	return nil
}

// baseName strips every directory component, whichever separator was used.
func baseName(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '/' || name[i] == '\\' {
			return name[i+1:]
		}
	}
	// A drive-relative name like "C:evil.txt" has no separator at all.
	if len(name) > 1 && name[1] == ':' {
		return name[2:]
	}
	return name
}
