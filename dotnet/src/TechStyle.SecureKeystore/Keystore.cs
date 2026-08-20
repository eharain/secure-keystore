using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace TechStyle.SecureKeystore;

/// <summary>One value and the file it lives in.</summary>
internal sealed class EntryRef
{
    [JsonPropertyName("key")] public string Key { get; set; } = "";
    [JsonPropertyName("file")] public string File { get; set; } = "";
}

/// <summary>
/// A store's master.json.
/// </summary>
/// <remarks>
/// <see cref="Extra"/> carries any field this build does not know about, because
/// a store written by a newer implementation must not be silently downgraded by
/// an older one that happens to write to it.
/// </remarks>
internal sealed class StoreMetadata
{
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("created")] public string? Created { get; set; }
    [JsonPropertyName("updated")] public string? Updated { get; set; }
    [JsonPropertyName("migrated")] public string? Migrated { get; set; }
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";
    [JsonPropertyName("iterations")] public int? Iterations { get; set; }
    [JsonPropertyName("master")] public Encrypted Master { get; set; } = new();
    [JsonPropertyName("entries")] public List<EntryRef> Entries { get; set; } = [];
    [JsonPropertyName("sourceFile")] public string? SourceFile { get; set; }
    [JsonPropertyName("totalKeys")] public int TotalKeys { get; set; }

    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    /// <summary>
    /// The store format this document is in. Absent means 1.0, which is the same
    /// on-disk shape as 2.0 - 2.0 only added optional fields.
    /// </summary>
    internal string FormatVersion => string.IsNullOrEmpty(Version) ? "1.0" : Version;

    /// <summary>True if this store predates format 3.0.</summary>
    internal bool IsLegacy => MajorOf(FormatVersion) < 3;

    /// <summary>
    /// The count this store was written with. Absent means it predates the field,
    /// and every version that did so used 100,000.
    /// </summary>
    internal int EffectiveIterations => Iterations ?? Format.LegacyIterations;

    internal int IvLength => IsLegacy ? Format.IvLengthLegacy : Format.IvLength;

    internal string MasterAad => IsLegacy ? "" : Format.ContextMaster;

    internal string ValueAad(string keyName) => IsLegacy ? "" : Format.ValueContext(keyName);

    internal static int MajorOf(string version)
    {
        var dot = version.IndexOf('.');
        var major = dot < 0 ? version : version[..dot];
        return int.TryParse(major, out var parsed) ? parsed : 0;
    }
}

/// <summary>One .enc file.</summary>
internal sealed class ValueRecord
{
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";

    /// <summary>
    /// Only meaningful to a 2.0 value, where the value key is stretched from the
    /// master key. A 3.0 value derives with HKDF, which takes no count, so the
    /// field is omitted rather than written as a number nothing reads.
    /// </summary>
    [JsonPropertyName("iterations")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public int? Iterations { get; set; }

    [JsonPropertyName("data")] public Encrypted Data { get; set; } = new();
}

/// <summary>
/// A secure key-value store backed by a directory.
/// </summary>
/// <remarks>
/// <para>
/// Two layers of encryption, and it is worth being precise about what the second
/// one buys. A user key unlocks the master key; the master key unlocks each
/// value. That is not defence in depth against a leaked user key - anyone
/// holding the user key reaches everything - it is what lets every value carry
/// its own salt and its own derived key, so no two values on disk share any
/// material and re-keying one value touches one file.
/// </para>
/// <para>
/// One instance binds one keystore directory and one set of options, validated
/// once in the constructor rather than on every call. It holds no secret of its
/// own - the user key is passed to each operation that needs it and is never
/// retained - so one instance built at start-up is safe to keep for the life of
/// the process.
/// </para>
/// <para>
/// This build writes format 3.0 and reads 3.0 and 2.0. A store is never half one
/// and half the other: writing to a 2.0 store keeps writing 2.0 records until
/// <see cref="Migrate"/> moves the whole thing across.
/// </para>
/// </remarks>
public sealed class Keystore
{
    private static readonly JsonSerializerOptions WriteJson = new()
    {
        WriteIndented = true,
        // Non-ASCII key names go in as themselves rather than as \uXXXX escapes,
        // which is what the other implementations write and what keeps a store
        // file readable.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly KeystoreOptions _options;

    /// <summary>Creates a keystore, validating the options once.</summary>
    public Keystore(KeystoreOptions? options = null)
    {
        _options = options ?? new KeystoreOptions();
        _options.Validate();

        if (_options.CreateDir)
        {
            Directory.CreateDirectory(_options.KeystoreDir);
        }
    }

    /// <summary>The keystore directory this instance is bound to.</summary>
    public string Dir => _options.KeystoreDir;

    /// <summary>The options this instance was built with.</summary>
    public KeystoreOptions Options => _options;

    private void Log(string message) => _options.Logger?.Invoke(message);

    private string StoreDir(string storeName) => Path.Combine(_options.KeystoreDir, storeName);

    private static string Now() => DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

    /// <summary>Reads and parses a store's master.json, or says which of the two is missing.</summary>
    private StoreMetadata ReadMetadata(string storeName)
    {
        var dir = StoreDir(storeName);
        if (!Directory.Exists(dir))
        {
            throw new KeystoreException(ErrorCodes.StoreNotFound, $"keystore \"{storeName}\" not found");
        }

        var masterPath = Path.Combine(dir, Format.MasterFile);
        if (!File.Exists(masterPath))
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt,
                $"keystore \"{storeName}\" has no {Format.MasterFile} - the directory exists but is not a store");
        }

        StoreMetadata? metadata;
        try
        {
            metadata = JsonSerializer.Deserialize<StoreMetadata>(File.ReadAllText(masterPath));
        }
        catch (JsonException cause)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt,
                $"{Format.MasterFile} in keystore \"{storeName}\" is not readable JSON",
                cause);
        }

        if (metadata is null)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt, $"{Format.MasterFile} in keystore \"{storeName}\" is empty");
        }

        if (StoreMetadata.MajorOf(metadata.FormatVersion) > StoreMetadata.MajorOf(Format.StoreVersion))
        {
            throw new KeystoreException(
                ErrorCodes.UnsupportedFormat,
                $"keystore \"{storeName}\" is in format {metadata.FormatVersion}, " +
                $"and this build reads up to {Format.StoreVersion}");
        }

        return metadata;
    }

    private void WriteMetadata(string storeName, StoreMetadata metadata)
    {
        metadata.Updated = Now();
        File.WriteAllText(
            Path.Combine(StoreDir(storeName), Format.MasterFile),
            JsonSerializer.Serialize(metadata, WriteJson));
    }

    /// <summary>Stretches the user key and decrypts the store's master key.</summary>
    private static string UnlockMaster(StoreMetadata metadata, string userKey, string storeName)
    {
        if (string.IsNullOrEmpty(userKey))
        {
            throw new KeystoreException(ErrorCodes.InvalidArgument, "a userKey is required to read this store");
        }

        byte[] salt;
        try
        {
            salt = Convert.FromHexString(metadata.Salt);
        }
        catch (FormatException cause)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt, $"keystore \"{storeName}\" has a malformed salt", cause);
        }

        var userDerived = Crypto.StretchPassword(userKey, salt, metadata.EffectiveIterations);

        try
        {
            return Crypto.Decrypt(metadata.Master, userDerived, metadata.MasterAad, "master key");
        }
        catch (KeystoreException error) when (error.Code == ErrorCodes.BadUserKey)
        {
            throw new KeystoreException(
                ErrorCodes.BadUserKey, $"wrong user key for keystore \"{storeName}\"", error);
        }
    }

    /// <summary>
    /// The key one value is encrypted under.
    /// </summary>
    /// <remarks>
    /// In 3.0 that is HKDF from the master key, with the value's salt and a
    /// context naming the key - so a value file moved to another key's name
    /// derives a different key entirely. In 2.0 it was PBKDF2 over the master
    /// key, at the store's full iteration count, with nothing binding it to the
    /// name.
    /// </remarks>
    private static byte[] ValueKey(
        string masterKey, byte[] salt, string keyName, StoreMetadata metadata, ValueRecord record) =>
        metadata.IsLegacy
            ? Crypto.StretchPassword(masterKey, salt, record.Iterations ?? metadata.EffectiveIterations)
            : Crypto.DeriveFromKey(masterKey, salt, Format.ValueContext(keyName));

    private string ReadValue(string storeName, EntryRef entry, string masterKey, StoreMetadata metadata)
    {
        var valuePath = Path.Combine(StoreDir(storeName), entry.File);
        if (!File.Exists(valuePath))
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt,
                $"key \"{entry.Key}\" is listed in {Format.MasterFile} but its file {entry.File} is missing");
        }

        ValueRecord? record;
        try
        {
            record = JsonSerializer.Deserialize<ValueRecord>(File.ReadAllText(valuePath));
        }
        catch (JsonException cause)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt, $"the file for key \"{entry.Key}\" is not readable JSON", cause);
        }

        if (record is null)
        {
            throw new KeystoreException(ErrorCodes.StoreCorrupt, $"the file for key \"{entry.Key}\" is empty");
        }

        byte[] salt;
        try
        {
            salt = Convert.FromHexString(record.Salt);
        }
        catch (FormatException cause)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt, $"the file for key \"{entry.Key}\" has a malformed salt", cause);
        }

        var key = ValueKey(masterKey, salt, entry.Key, metadata, record);
        return Crypto.Decrypt(record.Data, key, metadata.ValueAad(entry.Key), $"value for \"{entry.Key}\"");
    }

    private void WriteValue(
        string storeName, string fileName, string keyName, string value, string masterKey, StoreMetadata metadata)
    {
        var salt = Crypto.RandomBytes(Format.ValueSaltLength);

        var record = new ValueRecord
        {
            Salt = Convert.ToHexString(salt).ToLowerInvariant(),
            Iterations = metadata.IsLegacy ? metadata.EffectiveIterations : null
        };

        var key = ValueKey(masterKey, salt, keyName, metadata, record);
        record.Data = Crypto.Encrypt(value, key, metadata.IvLength, metadata.ValueAad(keyName));

        File.WriteAllText(
            Path.Combine(StoreDir(storeName), fileName),
            JsonSerializer.Serialize(record, WriteJson));
    }

    /// <summary>
    /// Encrypts a key-value file into a store, in format 3.0.
    /// </summary>
    /// <remarks>
    /// The input format follows the extension: .json an object, .env dotenv
    /// lines, anything else key:value lines with master: first. A null or empty
    /// <paramref name="storeName"/> defaults to the input file's base name.
    /// <para>
    /// Re-securing an existing store replaces it. The old .enc files go first, so
    /// a key dropped from the input does not linger on disk as an encrypted
    /// orphan that nothing references any more.
    /// </para>
    /// </remarks>
    public SecureResult Secure(string inputFile, string userKey, string? storeName = null)
    {
        if (string.IsNullOrEmpty(userKey))
        {
            throw new KeystoreException(ErrorCodes.InvalidArgument, "Secure requires a userKey");
        }

        var parsed = InputFile.Parse(inputFile);
        if (string.IsNullOrEmpty(parsed.MasterKey))
        {
            throw new KeystoreException(
                ErrorCodes.BadInput,
                "input must define a master key (e.g. \"master:...\" in .txt, \"master=...\" in .env, " +
                "or a \"master\" property in .json)");
        }

        if (parsed.Entries.Count == 0)
        {
            throw new KeystoreException(ErrorCodes.BadInput, "no key-value entries found in input file");
        }

        storeName = string.IsNullOrEmpty(storeName)
            ? Path.GetFileNameWithoutExtension(inputFile)
            : storeName;

        var dir = StoreDir(storeName);
        Directory.CreateDirectory(dir);

        foreach (var file in Directory.GetFiles(dir))
        {
            var name = Path.GetFileName(file);
            if (name.EndsWith(Format.ValueExtension, StringComparison.Ordinal) || name == Format.MasterFile)
            {
                File.Delete(file);
            }
        }

        var storeSalt = Crypto.RandomBytes(Format.StoreSaltLength);
        var userDerived = Crypto.StretchPassword(userKey, storeSalt, _options.Iterations);

        var metadata = new StoreMetadata
        {
            Version = Format.StoreVersion,
            Created = Now(),
            Salt = Convert.ToHexString(storeSalt).ToLowerInvariant(),
            Iterations = _options.Iterations,
            Master = Crypto.Encrypt(parsed.MasterKey, userDerived, Format.IvLength, Format.ContextMaster),
            Entries = [],
            SourceFile = Path.GetFileName(inputFile),
            TotalKeys = parsed.Entries.Count
        };

        var keys = new List<string>(parsed.Entries.Count);
        foreach (var entry in parsed.Entries)
        {
            var file = Crypto.SafeFileName(entry.Key);
            WriteValue(storeName, file, entry.Key, entry.Value, parsed.MasterKey, metadata);
            metadata.Entries.Add(new EntryRef { Key = entry.Key, File = file });
            keys.Add(entry.Key);
        }

        WriteMetadata(storeName, metadata);
        UpdateIndex(storeName, metadata);
        Log($"Secured {keys.Count} keys in keystore \"{storeName}\" at {dir}");

        return new SecureResult(storeName, dir, keys.Count, keys);
    }

    /// <summary>
    /// Decrypts and returns one value.
    /// </summary>
    /// <remarks>
    /// A null or empty <paramref name="storeName"/> searches every store. That is
    /// a convenience for a single-store setup and a trap for a multi-store one,
    /// where two stores may hold the same key name and the first match wins -
    /// name the store when it matters.
    /// </remarks>
    public string Get(string key, string userKey, string? storeName = null)
    {
        storeName = string.IsNullOrEmpty(storeName) ? FindStoreForKey(key) : storeName;

        var metadata = ReadMetadata(storeName);
        var entry = metadata.Entries.FirstOrDefault(candidate => candidate.Key == key)
            ?? throw new KeystoreException(
                ErrorCodes.KeyNotFound, $"key \"{key}\" not found in keystore \"{storeName}\"");

        return ReadValue(storeName, entry, UnlockMaster(metadata, userKey, storeName), metadata);
    }

    /// <summary>
    /// Decrypts every value in a store.
    /// </summary>
    /// <remarks>
    /// The user key is stretched once, not once per value, so this costs one
    /// PBKDF2 derivation however many keys the store holds.
    /// </remarks>
    public Dictionary<string, string> GetAll(string userKey, string storeName)
    {
        var metadata = ReadMetadata(storeName);
        var masterKey = UnlockMaster(metadata, userKey, storeName);

        var values = new Dictionary<string, string>(metadata.Entries.Count);
        foreach (var entry in metadata.Entries)
        {
            values[entry.Key] = ReadValue(storeName, entry, masterKey, metadata);
        }

        return values;
    }

    /// <summary>
    /// Adds a key, or replaces the value of one already there.
    /// </summary>
    /// <remarks>
    /// The replacement gets a fresh salt and a fresh IV, so an observer who kept
    /// the old file learns nothing by comparing it with the new one.
    /// <para>
    /// On a store still in format 2.0 this writes a 2.0 record, so the store
    /// stays internally consistent. Run <see cref="Migrate"/> to move the whole
    /// store to 3.0.
    /// </para>
    /// </remarks>
    public SetResult Set(string key, string value, string userKey, string storeName)
    {
        if (string.IsNullOrEmpty(key))
        {
            throw new KeystoreException(ErrorCodes.InvalidArgument, "Set requires a key");
        }

        var metadata = ReadMetadata(storeName);
        var masterKey = UnlockMaster(metadata, userKey, storeName);

        var existing = metadata.Entries.FirstOrDefault(entry => entry.Key == key);
        var file = existing?.File ?? Crypto.SafeFileName(key);

        WriteValue(storeName, file, key, value, masterKey, metadata);

        if (existing is null)
        {
            metadata.Entries.Add(new EntryRef { Key = key, File = file });
            metadata.TotalKeys = metadata.Entries.Count;
        }

        WriteMetadata(storeName, metadata);
        UpdateIndex(storeName, metadata);
        Log($"Key \"{key}\" {(existing is null ? "added" : "updated")} in keystore \"{storeName}\"");

        return new SetResult(key, storeName, existing is null, metadata.FormatVersion);
    }

    /// <summary>
    /// Rewrites a whole store in the current format.
    /// </summary>
    /// <remarks>
    /// Every value is decrypted with the old parameters and re-encrypted with the
    /// new ones, under a fresh store salt and fresh per-value salts. The master
    /// key itself does not change, so nothing outside the store has to be told.
    /// <para>
    /// A store already on the current format is re-encrypted rather than skipped,
    /// which is what makes this the way to raise a store's iteration count as
    /// well as its format.
    /// </para>
    /// <para>
    /// The rewrite is not atomic. Every value is decrypted before anything is
    /// written, so a wrong user key changes nothing; and every new value file is
    /// written before master.json, so an interruption leaves the store readable
    /// in its old format. Export first anyway.
    /// </para>
    /// </remarks>
    public MigrateResult Migrate(string storeName, string userKey)
    {
        var metadata = ReadMetadata(storeName);
        var from = metadata.FormatVersion;
        var masterKey = UnlockMaster(metadata, userKey, storeName);

        // Decrypt everything up front. If any value fails, the store is untouched.
        var values = metadata.Entries
            .Select(entry => (entry.Key, Value: ReadValue(storeName, entry, masterKey, metadata)))
            .ToList();

        var storeSalt = Crypto.RandomBytes(Format.StoreSaltLength);
        var userDerived = Crypto.StretchPassword(userKey, storeSalt, _options.Iterations);

        metadata.Version = Format.StoreVersion;
        metadata.Salt = Convert.ToHexString(storeSalt).ToLowerInvariant();
        metadata.Iterations = _options.Iterations;
        metadata.Master = Crypto.Encrypt(masterKey, userDerived, Format.IvLength, Format.ContextMaster);
        metadata.Migrated = Now();
        metadata.Entries = [];
        metadata.TotalKeys = values.Count;

        var dir = StoreDir(storeName);
        var stale = Directory
            .GetFiles(dir, "*" + Format.ValueExtension)
            .Select(Path.GetFileName)
            .OfType<string>()
            .ToHashSet();

        var keys = new List<string>(values.Count);
        foreach (var (key, value) in values)
        {
            var file = Crypto.SafeFileName(key);
            WriteValue(storeName, file, key, value, masterKey, metadata);
            metadata.Entries.Add(new EntryRef { Key = key, File = file });
            keys.Add(key);
            stale.Remove(file);
        }

        WriteMetadata(storeName, metadata);
        foreach (var file in stale)
        {
            File.Delete(Path.Combine(dir, file));
        }

        UpdateIndex(storeName, metadata);
        Log(from == Format.StoreVersion
            ? $"Keystore \"{storeName}\" re-encrypted in format {Format.StoreVersion} at {_options.Iterations} iterations"
            : $"Keystore \"{storeName}\" migrated from format {from} to {Format.StoreVersion}");

        return new MigrateResult(storeName, from, Format.StoreVersion, keys, _options.Iterations);
    }

    /// <summary>Removes one key and its encrypted file.</summary>
    public void DeleteKey(string key, string storeName)
    {
        var metadata = ReadMetadata(storeName);

        var entry = metadata.Entries.FirstOrDefault(candidate => candidate.Key == key)
            ?? throw new KeystoreException(
                ErrorCodes.KeyNotFound, $"key \"{key}\" not found in keystore \"{storeName}\"");

        metadata.Entries.Remove(entry);
        metadata.TotalKeys = metadata.Entries.Count;

        var valuePath = Path.Combine(StoreDir(storeName), entry.File);
        if (File.Exists(valuePath))
        {
            File.Delete(valuePath);
        }

        WriteMetadata(storeName, metadata);
        UpdateIndex(storeName, metadata);
        Log($"Key \"{key}\" deleted from keystore \"{storeName}\"");
    }

    /// <summary>
    /// The names of every store under this keystore directory.
    /// </summary>
    /// <remarks>
    /// A directory counts as a store only if it holds a master.json, so an
    /// unrelated directory sitting alongside is not reported as one.
    /// </remarks>
    public IReadOnlyList<string> ListStores()
    {
        if (!Directory.Exists(_options.KeystoreDir))
        {
            return [];
        }

        return Directory
            .GetDirectories(_options.KeystoreDir)
            .Where(dir => File.Exists(Path.Combine(dir, Format.MasterFile)))
            .Select(Path.GetFileName)
            .OfType<string>()
            .ToList();
    }

    /// <summary>
    /// The key names in a store.
    /// </summary>
    /// <remarks>
    /// No user key, and none is needed: names live in metadata in the clear. That
    /// is a deliberate trade - it is what makes listing useful without a password
    /// - and it means a key name must not itself be a secret.
    /// </remarks>
    public IReadOnlyList<string> ListKeys(string storeName) =>
        ReadMetadata(storeName).Entries.Select(entry => entry.Key).ToList();

    /// <summary>Everything about a store that can be known without decrypting anything.</summary>
    public StoreInfo GetStoreInfo(string storeName)
    {
        var metadata = ReadMetadata(storeName);

        return new StoreInfo(
            storeName,
            StoreDir(storeName),
            metadata.FormatVersion,
            !metadata.IsLegacy,
            metadata.Created ?? "",
            metadata.Updated ?? metadata.Created ?? "",
            metadata.EffectiveIterations,
            metadata.TotalKeys,
            metadata.Entries.Select(entry => entry.Key).ToList(),
            metadata.SourceFile ?? "");
    }

    /// <summary>
    /// Writes a store to a single portable bundle, .skb by default.
    /// </summary>
    /// <remarks>
    /// The contents are already encrypted, so the bundle is safe to move through
    /// a CI artifact store or an scp. A null or empty path writes into the
    /// working directory under a stamped name.
    /// </remarks>
    public string ExportStore(string storeName, string? backupPath = null)
    {
        ReadMetadata(storeName); // refuse early if it is not a store

        backupPath = string.IsNullOrEmpty(backupPath)
            ? Path.Combine(
                Directory.GetCurrentDirectory(),
                $"{storeName}-backup-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}{Format.DefaultBackupExtension}")
            : backupPath;

        var bundle = Bundle.Build(StoreDir(storeName), storeName);
        File.WriteAllText(backupPath, JsonSerializer.Serialize(bundle, WriteJson));

        Log($"Store \"{storeName}\" exported to {backupPath}");
        return backupPath;
    }

    /// <summary>Restores a bundle, under its own name or a new one.</summary>
    public string ImportStore(string backupPath, string? storeName = null)
    {
        var bundle = Bundle.Read(backupPath);

        var target = string.IsNullOrEmpty(storeName) ? bundle.StoreName : storeName;
        if (string.IsNullOrEmpty(target))
        {
            throw new KeystoreException(
                ErrorCodes.BadBackup,
                "cannot determine a target store name: the bundle names none and none was given");
        }

        Bundle.Write(bundle, StoreDir(target));
        UpdateIndex(target, ReadMetadata(target));

        Log($"Store imported as \"{target}\"");
        return target;
    }

    /// <summary>Removes a store and its index entry. There is no undo; export first.</summary>
    public void DeleteStore(string storeName)
    {
        ReadMetadata(storeName); // refuse to delete a directory that is not a store

        Directory.Delete(StoreDir(storeName), recursive: true);

        var indexPath = Path.Combine(_options.KeystoreDir, Format.IndexFile);
        if (File.Exists(indexPath))
        {
            try
            {
                var catalogue = JsonNode.Parse(File.ReadAllText(indexPath))?.AsObject();
                catalogue?["stores"]?.AsObject().Remove(storeName);
                if (catalogue is not null)
                {
                    catalogue["updated"] = Now();
                    File.WriteAllText(indexPath, catalogue.ToJsonString(WriteJson));
                }
            }
            catch (JsonException)
            {
                // A corrupt catalogue is not worth failing a delete over.
            }
        }

        Log($"Keystore \"{storeName}\" deleted");
    }

    /// <summary>Instance sugar for <see cref="ValueToken.Encrypt"/>.</summary>
    public string? EncryptValue(string? plaintext, string userKey, TokenOptions? options = null) =>
        ValueToken.Encrypt(plaintext, userKey, options);

    /// <summary>Instance sugar for <see cref="ValueToken.Decrypt"/>.</summary>
    public string? DecryptValue(string? token, string userKey) => ValueToken.Decrypt(token, userKey);

    /// <summary>
    /// Rewrites this store's entry in the keystore-wide catalogue.
    /// </summary>
    /// <remarks>
    /// The catalogue holds names and counts and no secrets, which is what makes
    /// it safe to read without a user key - and what makes it merely a
    /// convenience: every operation reads the store's own master.json for
    /// anything that matters.
    /// </remarks>
    private void UpdateIndex(string storeName, StoreMetadata metadata)
    {
        var indexPath = Path.Combine(_options.KeystoreDir, Format.IndexFile);

        JsonObject catalogue;
        try
        {
            catalogue = File.Exists(indexPath)
                ? JsonNode.Parse(File.ReadAllText(indexPath))?.AsObject() ?? []
                : [];
        }
        catch (JsonException)
        {
            // A corrupt catalogue is not worth failing a write over - it holds
            // nothing that is not also in each store's own metadata. Rebuild it.
            catalogue = [];
        }

        if (catalogue["stores"] is not JsonObject stores)
        {
            stores = [];
            catalogue["stores"] = stores;
        }

        stores[storeName] = new JsonObject
        {
            ["version"] = metadata.FormatVersion,
            ["created"] = metadata.Created,
            ["totalKeys"] = metadata.TotalKeys,
            ["keys"] = new JsonArray(metadata.Entries.Select(entry => JsonValue.Create(entry.Key)).ToArray<JsonNode?>()),
            ["sourceFile"] = metadata.SourceFile
        };
        catalogue["updated"] = Now();

        File.WriteAllText(indexPath, catalogue.ToJsonString(WriteJson));
    }

    /// <summary>The first store holding this key.</summary>
    private string FindStoreForKey(string key)
    {
        foreach (var storeName in ListStores())
        {
            try
            {
                if (ListKeys(storeName).Contains(key))
                {
                    return storeName;
                }
            }
            catch (KeystoreException)
            {
                // A store we cannot read is not a store that holds the key.
            }
        }

        throw new KeystoreException(ErrorCodes.KeyNotFound, $"key \"{key}\" not found in any keystore");
    }
}
