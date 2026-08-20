using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using TechStyle.SecureKeystore;

// The command line for the secure-keystore format.
//
//   dotnet tool install -g TechStyle.SecureKeystore.Cli
//
// The verbs, the error codes and the --json output match every other
// implementation, so a shell script should not be able to tell which one it is
// calling. Every line this program prints is printed here: the library takes a
// logger and is otherwise silent, which is what lets it drop into a server that
// has opinions about its own logging.

const string Name = "secure-keystore";

// Console output is UTF-8, whatever the host's code page says.
//
// On Windows the default is the OEM code page - 437 or 850 - which turns any
// character it cannot represent into a literal '?'. A secret containing an emoji
// or a Cyrillic key name would come back through `get` visibly correct in one
// implementation and as '????' here, and a script capturing that output would
// store the corruption. The store itself was always fine; this is the last six
// inches.
Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

var flags = new Flags();
var positional = new List<string>();

for (var i = 0; i < args.Length; i++)
{
    var arg = args[i];
    switch (arg)
    {
        case "--keystore" when i + 1 < args.Length:
            flags.Keystore = args[++i];
            break;
        case "--iterations" when i + 1 < args.Length:
            flags.Iterations = int.TryParse(args[++i], out var count) ? count : 0;
            break;
        case "--json":
            flags.Json = true;
            break;
        case "--quiet":
            flags.Quiet = true;
            break;
        case "--help" or "-h":
            flags.Help = true;
            break;
        case "--version" or "-v":
            flags.Version = true;
            break;
        default:
            if (arg.StartsWith("--keystore=", StringComparison.Ordinal))
            {
                flags.Keystore = arg["--keystore=".Length..];
            }
            else if (arg.StartsWith("--iterations=", StringComparison.Ordinal))
            {
                flags.Iterations = int.TryParse(arg["--iterations=".Length..], out var value) ? value : 0;
            }
            else
            {
                positional.Add(arg);
            }
            break;
    }
}

if (flags.Version)
{
    Console.WriteLine(CliVersion.Value);
    return 0;
}

if (flags.Help || positional.Count == 0)
{
    ShowHelp();
    return 0;
}

var writeJson = new JsonSerializerOptions
{
    WriteIndented = true,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
};

try
{
    var options = new KeystoreOptions();
    if (!string.IsNullOrEmpty(flags.Keystore))
    {
        options.KeystoreDir = Path.GetFullPath(flags.Keystore);
    }
    if (flags.Iterations > 0)
    {
        options.Iterations = flags.Iterations;
    }
    if (!flags.Quiet && !flags.Json)
    {
        options.Logger = Console.WriteLine;
    }

    var store = new Keystore(options);
    var command = positional[0];
    var rest = positional.Skip(1).ToList();

    // Each command hands over both forms of its result at once: text for a
    // person, data for a script. Which one is printed is decided in one place.
    int Emit(string text, object data)
    {
        Console.WriteLine(flags.Json ? JsonSerializer.Serialize(data, writeJson) : text);
        return 0;
    }

    switch (command)
    {
        case "secure":
        {
            if (rest.Count < 2) return Misuse("secure <input-file> <user-key> [store-name]");
            var result = store.Secure(rest[0], rest[1], rest.Count > 2 ? rest[2] : null);
            return Emit(string.Join('\n', result.Keys), new
            {
                storeName = result.StoreName,
                storeDir = result.StoreDir,
                totalKeys = result.TotalKeys,
                keys = result.Keys
            });
        }

        case "get":
        {
            if (rest.Count < 2) return Misuse("get <key> <user-key> [store-name]");
            var value = store.Get(rest[0], rest[1], rest.Count > 2 ? rest[2] : null);
            // The bare value, so KEY=$(secure-keystore get x "$K" prod) works.
            return Emit(value, new { key = rest[0], value });
        }

        case "all":
        {
            if (rest.Count < 2) return Misuse("all <store-name> <user-key>");
            var values = store.GetAll(rest[1], rest[0]);
            var text = string.Join('\n', values.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
            return Emit(text, new { store = rest[0], values });
        }

        case "set":
        {
            if (rest.Count < 4) return Misuse("set <key> <value> <user-key> <store-name>");
            var result = store.Set(rest[0], rest[1], rest[2], rest[3]);
            var verb = result.Added ? "added to" : "updated in";
            return Emit($"Key \"{result.Key}\" {verb} \"{result.StoreName}\"", new
            {
                key = result.Key,
                storeName = result.StoreName,
                added = result.Added,
                format = result.StoreFormat
            });
        }

        case "migrate":
        {
            if (rest.Count < 2) return Misuse("migrate <store-name> <user-key>");
            var result = store.Migrate(rest[0], rest[1]);
            var text = result.From == result.To
                ? $"Store \"{result.StoreName}\" re-encrypted in format {result.To} at {result.Iterations} iterations"
                : $"Store \"{result.StoreName}\" migrated from format {result.From} to {result.To}";
            return Emit(text, new
            {
                storeName = result.StoreName,
                from = result.From,
                to = result.To,
                keys = result.Keys,
                iterations = result.Iterations
            });
        }

        case "list":
        {
            if (rest.Count < 1) return Misuse("list <store-name>");
            var keys = store.ListKeys(rest[0]);
            return Emit(string.Join('\n', keys), new { store = rest[0], keys });
        }

        case "stores":
        {
            var infos = store.ListStores().Select(store.GetStoreInfo).ToList();
            var text = infos.Count == 0
                ? "No stores found"
                : string.Join('\n', infos.Select(info => $"{info.Name}  ({info.TotalKeys} keys)"));
            return Emit(text, new
            {
                stores = infos.Select(info => new
                {
                    name = info.Name,
                    version = info.Version,
                    current = info.Current,
                    totalKeys = info.TotalKeys
                })
            });
        }

        case "info":
        {
            if (rest.Count < 1) return Misuse("info <store-name>");
            var info = store.GetStoreInfo(rest[0]);
            var format = info.Current ? info.Version : $"{info.Version}  (run migrate to bring it to {Format.StoreVersion})";
            var text = string.Join('\n', [
                $"Name:        {info.Name}",
                $"Path:        {info.Path}",
                $"Format:      {format}",
                $"Created:     {info.Created}",
                $"Updated:     {info.Updated}",
                $"Iterations:  {info.Iterations}",
                $"Total keys:  {info.TotalKeys}",
                $"Keys:        {string.Join(", ", info.Keys)}",
                $"Source file: {info.SourceFile}"
            ]);
            return Emit(text, new
            {
                name = info.Name,
                path = info.Path,
                version = info.Version,
                current = info.Current,
                created = info.Created,
                updated = info.Updated,
                iterations = info.Iterations,
                totalKeys = info.TotalKeys,
                keys = info.Keys,
                sourceFile = info.SourceFile
            });
        }

        case "delete":
        {
            if (rest.Count < 2) return Misuse("delete <key> <store-name>");
            store.DeleteKey(rest[0], rest[1]);
            return Emit($"Key \"{rest[0]}\" deleted from \"{rest[1]}\"",
                new { key = rest[0], store = rest[1], deleted = true });
        }

        case "delete-store":
        {
            if (rest.Count < 1) return Misuse("delete-store <store-name>");
            store.DeleteStore(rest[0]);
            return Emit($"Keystore \"{rest[0]}\" deleted", new { store = rest[0], deleted = true });
        }

        case "export":
        {
            if (rest.Count < 1) return Misuse("export <store-name> [backup-path]");
            var written = store.ExportStore(rest[0], rest.Count > 1 ? rest[1] : null);
            return Emit(written, new { store = rest[0], path = written });
        }

        case "import":
        {
            if (rest.Count < 1) return Misuse("import <backup-path> [store-name]");
            var imported = store.ImportStore(rest[0], rest.Count > 1 ? rest[1] : null);
            return Emit($"Store imported as \"{imported}\"", new { store = imported });
        }

        case "encrypt":
        {
            if (rest.Count < 2) return Misuse("encrypt <value> <user-key>");
            var tokenOptions = flags.Iterations > 0 ? new TokenOptions { Iterations = flags.Iterations } : null;
            var token = ValueToken.Encrypt(rest[0], rest[1], tokenOptions);
            return Emit(token ?? "", new { token });
        }

        case "decrypt":
        {
            if (rest.Count < 2) return Misuse("decrypt <token> <user-key>");
            var value = ValueToken.Decrypt(rest[0], rest[1]);
            return Emit(value ?? "", new { value });
        }

        default:
            Console.Error.WriteLine($"Unknown command: {command}\n");
            ShowHelp();
            return 1;
    }
}
catch (KeystoreException error)
{
    // The code first, because the code is the half that is stable, and the same
    // line every implementation prints for the same failure.
    if (flags.Json)
    {
        Console.Error.WriteLine(JsonSerializer.Serialize(
            new { error = error.Message, code = error.Code }, writeJson));
    }
    else
    {
        Console.Error.WriteLine($"{error.Code}: {error.Message}");
    }
    return 1;
}
catch (Exception error)
{
    Console.Error.WriteLine(flags.Json
        ? JsonSerializer.Serialize(new { error = error.Message, code = "UNKNOWN" }, writeJson)
        : $"UNKNOWN: {error.Message}");
    return 1;
}

int Misuse(string line)
{
    Console.Error.WriteLine($"Usage: {Name} {line}");
    return 1;
}

void ShowHelp() => Console.WriteLine($"""

{Name} {CliVersion.Value} - encrypted secrets at rest, with no service to run

Usage:
  {Name} secure <input-file> <user-key> [store-name]
  {Name} get <key> <user-key> [store-name]
  {Name} all <store-name> <user-key>
  {Name} set <key> <value> <user-key> <store-name>
  {Name} migrate <store-name> <user-key>
  {Name} list <store-name>
  {Name} stores
  {Name} info <store-name>
  {Name} delete <key> <store-name>
  {Name} delete-store <store-name>
  {Name} export <store-name> [backup-path]
  {Name} import <backup-path> [store-name]
  {Name} encrypt <value> <user-key>
  {Name} decrypt <token> <user-key>
  {Name} --help | --version

Options:
  --keystore <dir>     where stores live (default ./.keystore)
  --iterations <n>     PBKDF2 rounds for new or migrated stores (default {Format.DefaultIterations})
  --json               print machine-readable JSON instead of prose
  --quiet              print results only, no progress

Examples:
  {Name} secure keys.env "$USER_KEY" production
  {Name} get api_key "$USER_KEY" production
  {Name} stores
  {Name} migrate production "$USER_KEY"

A key name is not a secret: 'list', 'stores' and 'info' read metadata and need
no user key. 'get', 'all', 'set' and 'migrate' decrypt, and do.
""");

/// <summary>The flags this command line accepts, ahead of or after the verb.</summary>
internal sealed class Flags
{
    public string Keystore { get; set; } = "";
    public int Iterations { get; set; }
    public bool Json { get; set; }
    public bool Quiet { get; set; }
    public bool Help { get; set; }
    public bool Version { get; set; }
}

/// <summary>The CLI's own version, which tracks the library's.</summary>
internal static class CliVersion
{
    public const string Value = "1.0.0";
}
