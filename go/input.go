package securekeystore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Reading an input file into a master key and a list of entries.
//
// Three formats, chosen by extension, all saying the same thing. They are
// parsed here rather than in the store so that each can be tested against a
// string, with no directory involved.

// InputFormat names one of the three shapes an input file can take.
type InputFormat string

const (
	// FormatColon is `master:<key>` on the first line, then `key:value` lines.
	FormatColon InputFormat = "colon"
	// FormatEnv is dotenv: `KEY=value`, with comments, quotes and `export`.
	FormatEnv InputFormat = "env"
	// FormatJSON is a flat object with a "master" property.
	FormatJSON InputFormat = "json"
)

// Entry is one key-value pair read out of an input file.
type Entry struct {
	Key   string
	Value string
}

// FormatFor reports the format an input file will be read as, from its
// extension. ".json" and ".env" are named; everything else is the colon format.
func FormatFor(inputFile string) InputFormat {
	switch strings.ToLower(filepath.Ext(inputFile)) {
	case ".json":
		return FormatJSON
	case ".env":
		return FormatEnv
	default:
		return FormatColon
	}
}

// ParseInput reads a file and parses it as whatever its extension says it is.
func ParseInput(inputFile string) (masterKey string, entries []Entry, err error) {
	content, err := os.ReadFile(inputFile)
	if err != nil {
		return "", nil, wrapf(CodeBadInput, err, "could not read input file: %s", inputFile)
	}
	return ParseText(string(content), FormatFor(inputFile))
}

// ParseText parses input text in a named format. The file-free half of
// [ParseInput].
func ParseText(content string, format InputFormat) (masterKey string, entries []Entry, err error) {
	switch format {
	case FormatJSON:
		return parseJSON(content)
	case FormatEnv:
		return parseEnv(content)
	case FormatColon:
		return parseColon(content)
	default:
		return "", nil, failf(CodeBadInput, "unknown input format: %s", format)
	}
}

// parseColon reads the default format: `master:<key>` first, then `key:value`.
//
// Only the first colon splits, so a value may contain as many more as it likes -
// which is what lets a URL or a connection string go in without escaping.
func parseColon(content string) (string, []Entry, error) {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) == 0 {
		return "", nil, failf(CodeBadInput, "input file is empty")
	}

	head, rest, found := strings.Cut(lines[0], ":")
	if !found || head != masterEntryKey {
		return "", nil, failf(CodeBadInput, `first line must be "%s:your_master_key"`, masterEntryKey)
	}
	masterKey := rest

	entries := make([]Entry, 0, len(lines)-1)
	for _, line := range lines[1:] {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		entries = append(entries, Entry{Key: key, Value: value})
	}

	return masterKey, entries, nil
}

// parseEnv reads dotenv syntax.
//
// Lines beginning "#" are skipped, as are lines with no "=" and lines with an
// empty key. A leading "export " is stripped. A matched pair of single or
// double quotes around the whole value is stripped - no escape sequences are
// interpreted. The master entry may appear anywhere.
func parseEnv(content string) (string, []Entry, error) {
	var (
		masterKey string
		entries   []Entry
	)

	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		line = strings.TrimSpace(line)

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			first, last := value[0], value[len(value)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		if key == masterEntryKey {
			masterKey = value
			continue
		}
		entries = append(entries, Entry{Key: key, Value: value})
	}

	return masterKey, entries, nil
}

// parseJSON reads a flat object.
//
// Values that are not strings are serialised to their JSON form rather than
// refused, so a port number or a feature flag lifted straight out of an existing
// config file goes in without being quoted first. Everything comes back out as
// a string, which is what the store holds.
//
// json.Decoder with UseNumber and a token stream keeps the document's key
// order, which encoding/json's map decoding would not - and order is what
// `entries` promises.
func parseJSON(content string) (string, []Entry, error) {
	decoder := json.NewDecoder(strings.NewReader(content))
	decoder.UseNumber()

	open, err := decoder.Token()
	if err != nil {
		return "", nil, wrapf(CodeBadInput, err, "invalid JSON input file")
	}
	if delim, ok := open.(json.Delim); !ok || delim != '{' {
		return "", nil, failf(CodeBadInput, "JSON input must be an object of key-value pairs")
	}

	var (
		masterKey string
		entries   []Entry
	)

	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return "", nil, wrapf(CodeBadInput, err, "invalid JSON input file")
		}
		name, _ := nameToken.(string)

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", nil, wrapf(CodeBadInput, err, "invalid JSON input file")
		}

		text := string(value)
		// A JSON string becomes its contents; anything else keeps its JSON form.
		if len(text) > 0 && text[0] == '"' {
			var unquoted string
			if err := json.Unmarshal(value, &unquoted); err != nil {
				return "", nil, wrapf(CodeBadInput, err, "invalid JSON input file")
			}
			text = unquoted
		}

		if name == masterEntryKey {
			masterKey = text
			continue
		}
		entries = append(entries, Entry{Key: name, Value: text})
	}

	return masterKey, entries, nil
}
