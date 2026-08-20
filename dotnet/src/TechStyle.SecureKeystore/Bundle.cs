using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechStyle.SecureKeystore;

/// <summary>
/// A whole store as one portable document.
/// </summary>
/// <remarks>
/// The contents are already encrypted, so a bundle is safe to put through a CI
/// artifact store or an scp, and useless to anyone who intercepts it without the
/// user key. It is pure JSON - no tar, no shell - so it behaves the same on every
/// platform.
/// </remarks>
public sealed class Bundle
{
    /// <summary>Always <see cref="Format.BackupFormat"/>. Checked before anything is written.</summary>
    [JsonPropertyName("format")] public string BundleFormat { get; set; } = Format.BackupFormat;

    /// <summary>The bundle format version.</summary>
    [JsonPropertyName("version")] public int Version { get; set; } = Format.BackupVersion;

    /// <summary>The store this bundle came from.</summary>
    [JsonPropertyName("storeName")] public string StoreName { get; set; } = "";

    /// <summary>Every file in the store directory, verbatim.</summary>
    [JsonPropertyName("files")] public Dictionary<string, string> Files { get; set; } = [];

    /// <summary>Reads every file in a store directory into a bundle.</summary>
    internal static Bundle Build(string storeDir, string storeName)
    {
        var bundle = new Bundle { StoreName = storeName };

        foreach (var path in Directory.GetFiles(storeDir))
        {
            bundle.Files[Path.GetFileName(path)] = File.ReadAllText(path);
        }

        return bundle;
    }

    /// <summary>
    /// Reads a bundle off disk and checks it is one of ours before any of it is
    /// believed.
    /// </summary>
    /// <remarks>
    /// The checks are in the order that matters: a file that is not JSON, a JSON
    /// document that is not a bundle, a bundle from a future version, and a
    /// bundle with no master.json are four different mistakes and each says so.
    /// </remarks>
    internal static Bundle Read(string backupPath)
    {
        if (!File.Exists(backupPath))
        {
            throw new KeystoreException(ErrorCodes.BadBackup, $"backup file not found: {backupPath}");
        }

        Bundle? bundle;
        try
        {
            bundle = JsonSerializer.Deserialize<Bundle>(File.ReadAllText(backupPath));
        }
        catch (JsonException cause)
        {
            throw new KeystoreException(
                ErrorCodes.BadBackup, $"invalid backup file: {backupPath} is not readable as JSON", cause);
        }

        if (bundle is null || bundle.BundleFormat != Format.BackupFormat)
        {
            throw new KeystoreException(
                ErrorCodes.BadBackup, $"invalid backup file: {backupPath} is not a keystore bundle");
        }

        if (bundle.Version > Format.BackupVersion)
        {
            throw new KeystoreException(
                ErrorCodes.UnsupportedFormat,
                $"backup was written in bundle format {bundle.Version}, " +
                $"and this build reads up to {Format.BackupVersion}");
        }

        if (!bundle.Files.ContainsKey(Format.MasterFile))
        {
            throw new KeystoreException(
                ErrorCodes.BadBackup, $"invalid backup: {Format.MasterFile} not found in bundle");
        }

        return bundle;
    }

    /// <summary>
    /// Writes a bundle's files into a target directory.
    /// </summary>
    /// <remarks>
    /// Every name is reduced to its base name first. A bundle is an untrusted
    /// file that arrived over a wire, and
    /// <c>{"files": {"../../.ssh/authorized_keys": "..."}}</c> is a bundle
    /// someone could write by hand.
    /// <para>
    /// <c>Path.GetFileName</c> alone is not enough for a Unix path arriving on
    /// Windows or the reverse, so both separators are handled explicitly.
    /// </para>
    /// </remarks>
    internal static void Write(Bundle bundle, string targetDir)
    {
        Directory.CreateDirectory(targetDir);

        foreach (var (name, content) in bundle.Files)
        {
            var safe = BaseName(name);
            if (safe is "" or "." or "..")
            {
                continue;
            }

            File.WriteAllText(Path.Combine(targetDir, safe), content);
        }
    }

    /// <summary>Strips every directory component, whichever separator was used.</summary>
    private static string BaseName(string name)
    {
        for (var i = name.Length - 1; i >= 0; i--)
        {
            if (name[i] is '/' or '\\')
            {
                return name[(i + 1)..];
            }
        }

        // A drive-relative name like "C:evil.txt" has no separator at all.
        return name.Length > 1 && name[1] == ':' ? name[2..] : name;
    }
}
