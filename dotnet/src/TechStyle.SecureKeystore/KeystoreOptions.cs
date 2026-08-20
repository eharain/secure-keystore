namespace TechStyle.SecureKeystore;

/// <summary>
/// What a keystore is allowed to do.
/// </summary>
/// <remarks>
/// Every property has a default, so <c>new Keystore()</c> is the common case and
/// stays a one-liner. Options are validated once, in the constructor, rather
/// than on every call - so a mistake surfaces where it was written instead of as
/// a store that quietly ends up somewhere unexpected.
/// </remarks>
public sealed class KeystoreOptions
{
    /// <summary>Where stores live. Defaults to <c>./.keystore</c>.</summary>
    public string KeystoreDir { get; set; } =
        Path.Combine(Directory.GetCurrentDirectory(), Format.DefaultKeystoreDirname);

    /// <summary>
    /// The PBKDF2 count the <em>user key</em> is stretched with, for new and
    /// migrated stores. It is recorded in the store, so raising it never orphans
    /// one written before.
    /// </summary>
    /// <remarks>
    /// It does not apply to value keys, which are derived with HKDF and take no
    /// count.
    /// </remarks>
    public int Iterations { get; set; } = Format.DefaultIterations;

    /// <summary>
    /// Called with one line of progress. Null means the library prints nothing
    /// at all, which is the default and what a server wants.
    /// </summary>
    public Action<string>? Logger { get; set; }

    /// <summary>Create the keystore directory if it is absent.</summary>
    public bool CreateDir { get; set; } = true;

    /// <summary>
    /// Checks that the options make sense.
    /// </summary>
    /// <exception cref="KeystoreException">With code <see cref="ErrorCodes.InvalidOptions"/>.</exception>
    public void Validate()
    {
        if (string.IsNullOrEmpty(KeystoreDir))
        {
            throw new KeystoreException(ErrorCodes.InvalidOptions, "KeystoreDir must be a non-empty path");
        }

        if (Iterations < Format.MinIterations)
        {
            throw new KeystoreException(
                ErrorCodes.InvalidOptions,
                $"Iterations must be at least {Format.MinIterations}, not {Iterations}");
        }
    }
}

/// <summary>What <see cref="Keystore.Secure"/> returns.</summary>
/// <param name="StoreName">The store that was written.</param>
/// <param name="StoreDir">Where it was written.</param>
/// <param name="TotalKeys">How many keys went in.</param>
/// <param name="Keys">Their names, in the order the input gave them.</param>
public sealed record SecureResult(string StoreName, string StoreDir, int TotalKeys, IReadOnlyList<string> Keys);

/// <summary>What <see cref="Keystore.Set"/> returns.</summary>
/// <param name="Key">The key that was written.</param>
/// <param name="StoreName">The store it went into.</param>
/// <param name="Added">True if the key was new, false if an existing value was replaced.</param>
/// <param name="StoreFormat">
/// The format the record was written in - a 2.0 store keeps taking 2.0 writes.
/// </param>
public sealed record SetResult(string Key, string StoreName, bool Added, string StoreFormat);

/// <summary>What <see cref="Keystore.Migrate"/> returns.</summary>
/// <param name="StoreName">The store that was rewritten.</param>
/// <param name="From">The format it was in before.</param>
/// <param name="To">The format it is in now.</param>
/// <param name="Keys">Every key that was carried across.</param>
/// <param name="Iterations">The PBKDF2 count it was rewritten with.</param>
public sealed record MigrateResult(
    string StoreName,
    string From,
    string To,
    IReadOnlyList<string> Keys,
    int Iterations);

/// <summary>Everything about a store that can be known without decrypting anything.</summary>
/// <param name="Name">The store's name.</param>
/// <param name="Path">Where it lives.</param>
/// <param name="Version">The store format, "3.0" for anything this build writes.</param>
/// <param name="Current">False if the store is still on 2.0 and would benefit from a migrate.</param>
/// <param name="Created">When it was first written.</param>
/// <param name="Updated">When it was last written.</param>
/// <param name="Iterations">The PBKDF2 count its user key is stretched with.</param>
/// <param name="TotalKeys">How many keys it holds.</param>
/// <param name="Keys">Their names.</param>
/// <param name="SourceFile">The input file it came from, for information only.</param>
public sealed record StoreInfo(
    string Name,
    string Path,
    string Version,
    bool Current,
    string Created,
    string Updated,
    int Iterations,
    int TotalKeys,
    IReadOnlyList<string> Keys,
    string SourceFile);

/// <summary>Options for <see cref="Keystore.EncryptValue(string, string, TokenOptions?)"/>.</summary>
public sealed class TokenOptions
{
    /// <summary>
    /// The PBKDF2 count. Defaults to <see cref="Format.DefaultIterations"/>.
    /// </summary>
    /// <remarks>
    /// Unlike a store, there is no master key here: every token is stretched
    /// straight from the user key, so the default cost is paid on every single
    /// value. Encrypting a whole column is the case where that matters, and this
    /// is the property for it - the count is recorded in the token, so
    /// decryption follows whatever was chosen.
    /// </remarks>
    public int Iterations { get; set; } = Format.DefaultIterations;
}
