// Command secure-keystore is the command line for the secure-keystore format.
//
//	go install github.com/eharain/secure-keystore/go/v3/cmd/secure-keystore@latest
//
// The verbs, the error codes and the --json output match every other
// implementation, so a shell script should not be able to tell which one it is
// calling.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	ks "github.com/eharain/secure-keystore/go/v3"
)

const name = "secure-keystore"

// Every line this program prints is printed here. The library takes a logger
// and is otherwise silent, which is what lets it drop into a server that has
// opinions about its own logging.

type flags struct {
	keystore   string
	iterations int
	json       bool
	quiet      bool
	help       bool
	version    bool
}

func usage() {
	fmt.Printf(`
%[1]s %[2]s - encrypted secrets at rest, with no service to run

Usage:
  %[1]s secure <input-file> <user-key> [store-name]
  %[1]s get <key> <user-key> [store-name]
  %[1]s all <store-name> <user-key>
  %[1]s set <key> <value> <user-key> <store-name>
  %[1]s migrate <store-name> <user-key>
  %[1]s list <store-name>
  %[1]s stores
  %[1]s info <store-name>
  %[1]s delete <key> <store-name>
  %[1]s delete-store <store-name>
  %[1]s export <store-name> [backup-path]
  %[1]s import <backup-path> [store-name]
  %[1]s encrypt <value> <user-key>
  %[1]s decrypt <token> <user-key>
  %[1]s --help | --version

Options:
  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default %[3]d)
  --json               print machine-readable JSON instead of prose
  --quiet              print results only, no progress

Examples:
  %[1]s secure keys.env "$USER_KEY" production
  %[1]s get api_key "$USER_KEY" production
  %[1]s stores
  %[1]s migrate production "$USER_KEY"

A key name is not a secret: 'list', 'stores' and 'info' read metadata and need
no user key. 'get', 'all', 'set' and 'migrate' decrypt, and do.
`, name, ks.Version, ks.DefaultIterations)
}

// parseArgs pulls the flags out of the arguments and leaves the positional ones
// behind. Written by hand rather than with the flag package, because flags may
// appear after the verb here and `flag` stops at the first non-flag argument.
func parseArgs(argv []string) (flags, []string) {
	var f flags
	var positional []string

	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--keystore" && i+1 < len(argv):
			i++
			f.keystore = argv[i]
		case strings.HasPrefix(arg, "--keystore="):
			f.keystore = strings.TrimPrefix(arg, "--keystore=")
		case arg == "--iterations" && i+1 < len(argv):
			i++
			f.iterations, _ = strconv.Atoi(argv[i])
		case strings.HasPrefix(arg, "--iterations="):
			f.iterations, _ = strconv.Atoi(strings.TrimPrefix(arg, "--iterations="))
		case arg == "--json":
			f.json = true
		case arg == "--quiet":
			f.quiet = true
		case arg == "--help", arg == "-h":
			f.help = true
		case arg == "--version", arg == "-v":
			f.version = true
		default:
			positional = append(positional, arg)
		}
	}

	return f, positional
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	f, positional := parseArgs(argv)

	if f.version {
		fmt.Println(ks.Version)
		return 0
	}
	if f.help || len(positional) == 0 {
		usage()
		return 0
	}

	options := ks.DefaultOptions()
	if f.keystore != "" {
		absolute, err := filepath.Abs(f.keystore)
		if err != nil {
			return fail(f, err)
		}
		options.KeystoreDir = absolute
	}
	if f.iterations != 0 {
		options.Iterations = f.iterations
	}
	if !f.quiet && !f.json {
		options.Logger = func(message string) { fmt.Println(message) }
	}

	store, err := ks.New(options)
	if err != nil {
		return fail(f, err)
	}

	command, args := positional[0], positional[1:]

	// Each command hands over both forms of its result at once: text for a
	// person, data for a script. Which one is printed is decided in one place.
	emit := func(text string, data map[string]any) int {
		if f.json {
			encoded, err := json.MarshalIndent(data, "", "  ")
			if err != nil {
				return fail(f, err)
			}
			fmt.Println(string(encoded))
			return 0
		}
		fmt.Println(text)
		return 0
	}

	switch command {
	case "secure":
		if len(args) < 2 {
			return misuse("secure <input-file> <user-key> [store-name]")
		}
		storeName := ""
		if len(args) > 2 {
			storeName = args[2]
		}
		result, err := store.Secure(args[0], args[1], storeName)
		if err != nil {
			return fail(f, err)
		}
		return emit(strings.Join(result.Keys, "\n"), map[string]any{
			"storeName": result.StoreName,
			"storeDir":  result.StoreDir,
			"totalKeys": result.TotalKeys,
			"keys":      result.Keys,
		})

	case "get":
		if len(args) < 2 {
			return misuse("get <key> <user-key> [store-name]")
		}
		storeName := ""
		if len(args) > 2 {
			storeName = args[2]
		}
		value, err := store.Get(args[0], args[1], storeName)
		if err != nil {
			return fail(f, err)
		}
		// The bare value, so KEY=$(secure-keystore get x "$K" prod) works.
		return emit(value, map[string]any{"key": args[0], "value": value})

	case "all":
		if len(args) < 2 {
			return misuse("all <store-name> <user-key>")
		}
		values, err := store.GetAll(args[1], args[0])
		if err != nil {
			return fail(f, err)
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		lines := make([]string, 0, len(keys))
		for _, key := range keys {
			lines = append(lines, key+"="+values[key])
		}
		return emit(strings.Join(lines, "\n"), map[string]any{"store": args[0], "values": values})

	case "set":
		if len(args) < 4 {
			return misuse("set <key> <value> <user-key> <store-name>")
		}
		result, err := store.Set(args[0], args[1], args[2], args[3])
		if err != nil {
			return fail(f, err)
		}
		verb := "updated in"
		if result.Added {
			verb = "added to"
		}
		return emit(fmt.Sprintf("Key %q %s %q", result.Key, verb, result.StoreName), map[string]any{
			"key": result.Key, "storeName": result.StoreName,
			"added": result.Added, "format": result.Format,
		})

	case "migrate":
		if len(args) < 2 {
			return misuse("migrate <store-name> <user-key>")
		}
		result, err := store.Migrate(args[0], args[1])
		if err != nil {
			return fail(f, err)
		}
		text := fmt.Sprintf("Store %q migrated from format %s to %s", result.StoreName, result.From, result.To)
		if result.From == result.To {
			text = fmt.Sprintf("Store %q re-encrypted in format %s at %d iterations",
				result.StoreName, result.To, result.Iterations)
		}
		return emit(text, map[string]any{
			"storeName": result.StoreName, "from": result.From, "to": result.To,
			"keys": result.Keys, "iterations": result.Iterations,
		})

	case "list":
		if len(args) < 1 {
			return misuse("list <store-name>")
		}
		keys, err := store.ListKeys(args[0])
		if err != nil {
			return fail(f, err)
		}
		return emit(strings.Join(keys, "\n"), map[string]any{"store": args[0], "keys": keys})

	case "stores":
		names, err := store.ListStores()
		if err != nil {
			return fail(f, err)
		}
		infos := make([]any, 0, len(names))
		lines := make([]string, 0, len(names))
		for _, storeName := range names {
			info, err := store.StoreInfo(storeName)
			if err != nil {
				continue
			}
			infos = append(infos, map[string]any{
				"name": info.Name, "version": info.Version,
				"current": info.Current, "totalKeys": info.TotalKeys,
			})
			lines = append(lines, fmt.Sprintf("%s  (%d keys)", info.Name, info.TotalKeys))
		}
		text := strings.Join(lines, "\n")
		if text == "" {
			text = "No stores found"
		}
		return emit(text, map[string]any{"stores": infos})

	case "info":
		if len(args) < 1 {
			return misuse("info <store-name>")
		}
		info, err := store.StoreInfo(args[0])
		if err != nil {
			return fail(f, err)
		}
		format := info.Version
		if !info.Current {
			format += "  (run migrate to bring it to " + ks.StoreFormatVersion + ")"
		}
		text := strings.Join([]string{
			"Name:        " + info.Name,
			"Path:        " + info.Path,
			"Format:      " + format,
			"Created:     " + info.Created,
			"Updated:     " + info.Updated,
			"Iterations:  " + strconv.Itoa(info.Iterations),
			"Total keys:  " + strconv.Itoa(info.TotalKeys),
			"Keys:        " + strings.Join(info.Keys, ", "),
			"Source file: " + info.SourceFile,
		}, "\n")
		return emit(text, map[string]any{
			"name": info.Name, "path": info.Path, "version": info.Version,
			"current": info.Current, "created": info.Created, "updated": info.Updated,
			"iterations": info.Iterations, "totalKeys": info.TotalKeys,
			"keys": info.Keys, "sourceFile": info.SourceFile,
		})

	case "delete":
		if len(args) < 2 {
			return misuse("delete <key> <store-name>")
		}
		if err := store.DeleteKey(args[0], args[1]); err != nil {
			return fail(f, err)
		}
		return emit(fmt.Sprintf("Key %q deleted from %q", args[0], args[1]),
			map[string]any{"key": args[0], "store": args[1], "deleted": true})

	case "delete-store":
		if len(args) < 1 {
			return misuse("delete-store <store-name>")
		}
		if err := store.DeleteStore(args[0]); err != nil {
			return fail(f, err)
		}
		return emit(fmt.Sprintf("Keystore %q deleted", args[0]),
			map[string]any{"store": args[0], "deleted": true})

	case "export":
		if len(args) < 1 {
			return misuse("export <store-name> [backup-path]")
		}
		backupPath := ""
		if len(args) > 1 {
			backupPath = args[1]
		}
		written, err := store.ExportStore(args[0], backupPath)
		if err != nil {
			return fail(f, err)
		}
		return emit(written, map[string]any{"store": args[0], "path": written})

	case "import":
		if len(args) < 1 {
			return misuse("import <backup-path> [store-name]")
		}
		storeName := ""
		if len(args) > 1 {
			storeName = args[1]
		}
		imported, err := store.ImportStore(args[0], storeName)
		if err != nil {
			return fail(f, err)
		}
		return emit(fmt.Sprintf("Store imported as %q", imported), map[string]any{"store": imported})

	case "encrypt":
		if len(args) < 2 {
			return misuse("encrypt <value> <user-key>")
		}
		var tokenOptions []ks.TokenOptions
		if f.iterations != 0 {
			tokenOptions = append(tokenOptions, ks.TokenOptions{Iterations: f.iterations})
		}
		token, err := ks.EncryptValue(args[0], args[1], tokenOptions...)
		if err != nil {
			return fail(f, err)
		}
		return emit(token, map[string]any{"token": token})

	case "decrypt":
		if len(args) < 2 {
			return misuse("decrypt <token> <user-key>")
		}
		value, err := ks.DecryptValue(args[0], args[1])
		if err != nil {
			return fail(f, err)
		}
		return emit(value, map[string]any{"value": value})

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		usage()
		return 1
	}
}

func misuse(line string) int {
	fmt.Fprintf(os.Stderr, "Usage: %s %s\n", name, line)
	return 1
}

// fail prints an error the way a script can read it: the code first, because
// the code is the half that is stable, and the same line every implementation
// prints for the same failure.
//
// Error() carries the code too, which is right for a Go caller logging it and
// wrong here - so the message is taken on its own rather than printed twice.
func fail(f flags, err error) int {
	code := ks.CodeOf(err)
	if code == "" {
		code = "UNKNOWN"
	}

	message := err.Error()
	var typed *ks.Error
	if errors.As(err, &typed) && typed.Message != "" {
		message = typed.Message
	}

	if f.json {
		encoded, _ := json.MarshalIndent(map[string]any{
			"error": message,
			"code":  string(code),
		}, "", "  ")
		fmt.Fprintln(os.Stderr, string(encoded))
	} else {
		fmt.Fprintf(os.Stderr, "%s: %s\n", code, message)
	}

	return 1
}
