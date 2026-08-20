namespace TechStyle.SecureKeystore;

/// <summary>
/// Wire-format constants for the secure-keystore format.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here is a tuning knob. These are the values that define what a store
/// written by this library looks like, and changing one changes what the other
/// five implementations can read - which is why they live in one file rather
/// than scattered through the code that happens to use them.
/// </para>
/// <para>
/// Two format versions appear throughout. 3.0 is what this build writes; 2.0 is
/// what earlier releases wrote and what this build still reads. Everywhere the
/// two differ, the legacy value is named <c>*Legacy</c> and the difference is a
/// parameter rather than a separate code path.
/// </para>
/// </remarks>
public static class Format
{
    /// <summary>The store format stamped into every master.json this build writes.</summary>
    public const string StoreVersion = "3.0";

    /// <summary>
    /// The older format this build still reads and, on a store already written
    /// that way, still writes.
    /// </summary>
    public const string StoreVersionLegacy = "2.0";

    /// <summary>Identifies an export bundle, checked before anything is written to disk.</summary>
    public const string BackupFormat = "secure-keystore-backup";

    /// <summary>The bundle format this build writes and the highest it reads.</summary>
    public const int BackupVersion = 1;

    /// <summary>
    /// The current value-token prefix. skv2 records its own iteration count,
    /// which is the one thing skv1 got wrong: a token that cannot say how it was
    /// derived is a token whose parameters can never change.
    /// </summary>
    /// <remarks>
    /// <code>
    /// skv2:&lt;iterations&gt;:&lt;salt&gt;:&lt;iv&gt;:&lt;authTag&gt;:&lt;ciphertext&gt;
    /// skv1:&lt;salt&gt;:&lt;iv&gt;:&lt;authTag&gt;:&lt;ciphertext&gt;
    /// </code>
    /// </remarks>
    public const string TokenPrefix = "skv2";

    /// <summary>The older token prefix, read but never written.</summary>
    public const string TokenPrefixLegacy = "skv1";

    internal const int TokenParts = 6;
    internal const int TokenPartsLegacy = 5;

    /// <summary>AES-256: a 32-byte key.</summary>
    internal const int KeyLength = 32;

    /// <summary>
    /// 12 bytes, which is what NIST SP 800-38D recommends for GCM and - the
    /// reason this library exists at all in .NET - the only length
    /// <see cref="System.Security.Cryptography.AesGcm"/> will accept.
    /// <c>AesGcm.NonceByteSizes</c> is 12 to 12.
    /// </summary>
    internal const int IvLength = 12;

    /// <summary>
    /// The 16 bytes format 2.0 wrote. AesGcm cannot process one, so a 2.0 store
    /// is handled by <c>LegacyGcm</c> - see that class for why.
    /// </summary>
    internal const int IvLengthLegacy = 16;

    /// <summary>The GCM tag length, and the only one this format uses.</summary>
    internal const int AuthTagLength = 16;

    /// <summary>
    /// What a new store stretches the user key with, following OWASP's 2023
    /// guidance for PBKDF2-HMAC-SHA256.
    /// </summary>
    public const int DefaultIterations = 600_000;

    /// <summary>The floor below which the option is refused.</summary>
    public const int MinIterations = 10_000;

    /// <summary>Assumed for any 2.0 record written before the count was recorded.</summary>
    internal const int LegacyIterations = 100_000;

    /// <summary>Fixed by the skv1 layout, which has no field to record a count in.</summary>
    internal const int TokenIterationsLegacy = 100_000;

    internal const int StoreSaltLength = 32;
    internal const int ValueSaltLength = 32;

    /// <summary>
    /// 16, because the token carries its salt inline, in hex, in every stored
    /// value. Fixed by the layout rather than by taste.
    /// </summary>
    internal const int TokenSaltLength = 16;

    /// <summary>
    /// Domain-separation contexts, used as GCM additional authenticated data
    /// and, for a value, as the HKDF info as well.
    /// </summary>
    /// <remarks>
    /// This is what closes the gap 2.0 had: there, the tag covered the
    /// ciphertext and nothing else, so anyone who could write to a store could
    /// swap two value files and both would decrypt - under each other's names.
    /// </remarks>
    internal const string ContextMaster = "secure-keystore:v3:master";

    internal const string ContextValuePrefix = "secure-keystore:v3:value:";
    internal const string ContextToken = "secure-keystore:v3:token";

    /// <summary>The full context string binding a value to its key name.</summary>
    internal static string ValueContext(string keyName) => ContextValuePrefix + keyName;

    /// <summary>Catalogue of stores: names and key names, no secrets.</summary>
    internal const string IndexFile = "index.json";

    /// <summary>Per-store metadata and the encrypted master key.</summary>
    internal const string MasterFile = "master.json";

    /// <summary>One authenticated-encrypted file per value.</summary>
    internal const string ValueExtension = ".enc";

    /// <summary>Created under the working directory when no keystore directory is given.</summary>
    public const string DefaultKeystoreDirname = ".keystore";

    /// <summary>What ExportStore writes when given no path.</summary>
    public const string DefaultBackupExtension = ".skb";

    internal const string MasterEntryKey = "master";

    internal const int FilenameStemLimit = 64;
    internal const int FilenameHashLength = 8;
}
