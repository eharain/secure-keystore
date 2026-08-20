using System.Globalization;

namespace TechStyle.SecureKeystore;

/// <summary>
/// Encryption with no store behind it.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Keystore"/> owns a directory. These methods own nothing: they take
/// a secret and a user key and give back a string, which the caller puts
/// wherever it already keeps things - a database column, a config row, a queue
/// message. There is no master key and no file, so there is also no keystore to
/// deploy alongside the application.
/// </para>
/// <para>
/// The token is self-describing, and says so in its first field:
/// </para>
/// <code>
/// skv2:&lt;iterations&gt;:&lt;salt&gt;:&lt;iv&gt;:&lt;authTag&gt;:&lt;ciphertext&gt;   written and read
/// skv1:&lt;salt&gt;:&lt;iv&gt;:&lt;authTag&gt;:&lt;ciphertext&gt;                read only
/// </code>
/// <para>
/// What skv1 lacked was a field for its iteration count, which is why its count
/// is frozen at 100,000 forever and skv2's is not.
/// </para>
/// </remarks>
public static class ValueToken
{
    /// <summary>Reports whether the value is a token this format defines, of either version.</summary>
    public static bool IsEncryptedValue(string? value) =>
        value is not null &&
        (value.StartsWith(Format.TokenPrefix + ":", StringComparison.Ordinal) ||
         value.StartsWith(Format.TokenPrefixLegacy + ":", StringComparison.Ordinal));

    /// <summary>Returns "skv2", "skv1", or null if the value is not a token.</summary>
    public static string? TokenVersion(string? value) =>
        IsEncryptedValue(value) ? value![..value!.IndexOf(':')] : null;

    /// <summary>
    /// Encrypts one string under a user key, with nothing on disk.
    /// </summary>
    /// <remarks>
    /// A fresh random salt stretches the key and a fresh random IV feeds
    /// AES-256-GCM, so encrypting the same secret twice gives two different
    /// tokens - which is what stops a database column from revealing which rows
    /// share a value.
    /// <para>
    /// Null and the empty string are returned unchanged, matching every other
    /// implementation, so this can be mapped over a record without first sorting
    /// the empty fields out of it.
    /// </para>
    /// </remarks>
    public static string? Encrypt(string? plaintext, string userKey, TokenOptions? options = null)
    {
        if (string.IsNullOrEmpty(plaintext))
        {
            return plaintext;
        }

        if (string.IsNullOrEmpty(userKey))
        {
            throw new KeystoreException(ErrorCodes.InvalidArgument, "EncryptValue requires a userKey");
        }

        var iterations = options?.Iterations ?? Format.DefaultIterations;
        if (iterations < Format.MinIterations)
        {
            throw new KeystoreException(
                ErrorCodes.InvalidArgument,
                $"iterations must be at least {Format.MinIterations}, not {iterations}");
        }

        var salt = Crypto.RandomBytes(Format.TokenSaltLength);
        var key = Crypto.StretchPassword(userKey, salt, iterations);
        var record = Crypto.Encrypt(plaintext, key, Format.IvLength, Format.ContextToken);

        return string.Join(':', [
            Format.TokenPrefix,
            iterations.ToString(CultureInfo.InvariantCulture),
            Convert.ToHexString(salt).ToLowerInvariant(),
            record.Iv,
            record.AuthTag,
            record.Data
        ]);
    }

    /// <summary>
    /// Reverses <see cref="Encrypt"/>, for either token version.
    /// </summary>
    /// <remarks>
    /// Anything that is not a token is returned unchanged, so a column part way
    /// through being encrypted can be read with one call rather than a
    /// conditional at every site. A token that is malformed, altered, or written
    /// under a different user key throws - that case is never silently passed
    /// through, because doing so would hand the caller ciphertext it believed
    /// was plaintext.
    /// </remarks>
    public static string? Decrypt(string? token, string userKey)
    {
        if (!IsEncryptedValue(token))
        {
            return token;
        }

        if (string.IsNullOrEmpty(userKey))
        {
            throw new KeystoreException(ErrorCodes.InvalidArgument, "DecryptValue requires a userKey");
        }

        var parts = token!.Split(':');
        var legacy = parts[0] == Format.TokenPrefixLegacy;
        var expected = legacy ? Format.TokenPartsLegacy : Format.TokenParts;

        if (parts.Length != expected)
        {
            throw new KeystoreException(
                ErrorCodes.BadToken,
                $"not a {parts[0]} token: expected {expected} colon-separated fields, found {parts.Length}");
        }

        int iterations;
        string saltHex;
        Encrypted record;
        string aad;

        if (legacy)
        {
            // skv1 has no iteration field, and every one ever written used
            // 100,000. It also predates additional authenticated data and the
            // 12-byte IV; both are read as they were written.
            iterations = Format.TokenIterationsLegacy;
            saltHex = parts[1];
            record = new Encrypted { Iv = parts[2], AuthTag = parts[3], Data = parts[4] };
            aad = "";
        }
        else
        {
            if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out iterations) ||
                iterations < 1)
            {
                throw new KeystoreException(
                    ErrorCodes.BadToken,
                    $"token iteration count is not a positive whole number: \"{parts[1]}\"");
            }

            saltHex = parts[2];
            record = new Encrypted { Iv = parts[3], AuthTag = parts[4], Data = parts[5] };
            aad = Format.ContextToken;
        }

        byte[] salt;
        try
        {
            salt = Convert.FromHexString(saltHex);
        }
        catch (FormatException cause)
        {
            throw new KeystoreException(ErrorCodes.BadToken, "token salt is not hex", cause);
        }

        var key = Crypto.StretchPassword(userKey, salt, iterations);
        return Crypto.Decrypt(record, key, aad, "value");
    }
}
