namespace TechStyle.SecureKeystore;

/// <summary>
/// Every code a <see cref="KeystoreException"/> can carry.
/// </summary>
/// <remarks>
/// These strings are identical in every implementation of the format:
/// <c>BAD_USER_KEY</c> means the same thing in .NET, Go, Python, PHP, Rust and
/// JavaScript, and a script that greps for it keeps working when the team
/// rewrites the service. The message may be reworded between releases; the code
/// will not be.
/// </remarks>
public static class ErrorCodes
{
    /// <summary>The options given do not make sense.</summary>
    public const string InvalidOptions = "INVALID_OPTIONS";

    /// <summary>A required argument was missing or empty.</summary>
    public const string InvalidArgument = "INVALID_ARGUMENT";

    /// <summary>No such store under this keystore directory.</summary>
    public const string StoreNotFound = "STORE_NOT_FOUND";

    /// <summary>The directory exists but is not a store, or its metadata is unreadable.</summary>
    public const string StoreCorrupt = "STORE_CORRUPT";

    /// <summary>No such key - in the named store, or in any of them.</summary>
    public const string KeyNotFound = "KEY_NOT_FOUND";

    /// <summary>Decryption failed: the key is wrong, or the bytes have been altered.</summary>
    public const string BadUserKey = "BAD_USER_KEY";

    /// <summary>A value token is not in the form this format defines.</summary>
    public const string BadToken = "BAD_TOKEN";

    /// <summary>The input file is not readable as the format its extension claims.</summary>
    public const string BadInput = "BAD_INPUT";

    /// <summary>The bundle is missing, unreadable, or not a keystore bundle.</summary>
    public const string BadBackup = "BAD_BACKUP";

    /// <summary>The store or bundle is in a format version newer than this build reads.</summary>
    public const string UnsupportedFormat = "UNSUPPORTED_FORMAT";
}

/// <summary>
/// Thrown by every operation in this library that can fail in a way the caller
/// might want to handle rather than merely report.
/// </summary>
/// <remarks>
/// A wrong user key would otherwise surface as
/// <see cref="System.Security.Cryptography.AuthenticationTagMismatchException"/>,
/// which says nothing about which store or why. It becomes
/// <see cref="ErrorCodes.BadUserKey"/> here, naming the store, with the original
/// kept as the inner exception.
/// </remarks>
public sealed class KeystoreException : Exception
{
    /// <summary>A stable identifier from <see cref="ErrorCodes"/>.</summary>
    public string Code { get; }

    /// <summary>Creates an exception carrying a code.</summary>
    public KeystoreException(string code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <inheritdoc />
    public override string ToString() => $"{Code}: {Message}";
}
