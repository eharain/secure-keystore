using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace TechStyle.SecureKeystore;

/// <summary>One AES-GCM result, as it appears in a store file. Every field is lowercase hex.</summary>
/// <remarks>
/// The names are spelled out rather than left to the serialiser. System.Text.Json
/// neither matches nor emits camelCase by default, so without these a .NET store
/// would carry <c>Iv</c> where every other implementation writes <c>iv</c> - and
/// would read neither.
/// </remarks>
internal sealed class Encrypted
{
    [JsonPropertyName("iv")] public string Iv { get; set; } = "";
    [JsonPropertyName("authTag")] public string AuthTag { get; set; } = "";
    [JsonPropertyName("data")] public string Data { get; set; } = "";
}

/// <summary>
/// The cryptographic primitives, and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// Every AES call in this library goes through this class, so there is exactly
/// one place where an algorithm, an IV length or an encoding is chosen.
/// </para>
/// <para>
/// Two derivations, for two different jobs, which format 2.0 conflated.
/// <see cref="StretchPassword"/> turns a password into a key and is deliberately
/// slow; <see cref="DeriveFromKey"/> turns a key into another key and is fast,
/// because the input is already high-entropy and stretching it buys nothing.
/// Running 600,000 PBKDF2 rounds on the master key once per value - which 2.0
/// did - costs seconds on a store of any size and adds no security the master
/// key did not already have.
/// </para>
/// </remarks>
internal static class Crypto
{
    /// <summary>PBKDF2-HMAC-SHA256: a password, stretched.</summary>
    /// <remarks>
    /// The count is a parameter because it is recorded alongside whatever it
    /// derives. Deriving with a count that does not match the one a record was
    /// written with produces a different key, and the GCM tag then rejects it -
    /// which is the failure you want rather than the one where it nearly works.
    /// </remarks>
    internal static byte[] StretchPassword(string password, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            Format.KeyLength);

    /// <summary>HKDF-SHA256: one key into another, bound to a context.</summary>
    /// <remarks>
    /// The input is the master key, which is already a strong secret, so there is
    /// nothing to stretch - the job is separation, not hardening. <c>info</c>
    /// carries the context that separates them, and for a value that context
    /// contains the key name, which is half of what stops two value files being
    /// swapped. The other half is the same string passed as GCM additional data.
    /// </remarks>
    internal static byte[] DeriveFromKey(string key, byte[] salt, string info) =>
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(key),
            Format.KeyLength,
            salt,
            Encoding.UTF8.GetBytes(info));

    /// <summary>Random bytes from the system source.</summary>
    internal static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    /// <summary>
    /// Seals a plaintext under a fresh random IV, so the same plaintext under the
    /// same key never produces the same bytes twice.
    /// </summary>
    /// <remarks>
    /// <paramref name="aad"/> is the context binding, empty for a format 2.0
    /// record, which bound nothing.
    /// </remarks>
    internal static Encrypted Encrypt(string plaintext, byte[] key, int ivLength, string aad)
    {
        var iv = RandomBytes(ivLength);
        var data = Encoding.UTF8.GetBytes(plaintext);
        var associated = aad.Length == 0 ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(aad);

        var ciphertext = new byte[data.Length];
        var tag = new byte[Format.AuthTagLength];

        if (ivLength == Format.IvLength)
        {
            using var gcm = new AesGcm(key, Format.AuthTagLength);
            gcm.Encrypt(iv, data, ciphertext, tag, associated);
        }
        else
        {
            // AesGcm will not take this nonce length. See LegacyGcm.
            LegacyGcm.Encrypt(key, iv, data, associated, ciphertext, tag);
        }

        return new Encrypted
        {
            Iv = Convert.ToHexString(iv).ToLowerInvariant(),
            AuthTag = Convert.ToHexString(tag).ToLowerInvariant(),
            Data = Convert.ToHexString(ciphertext).ToLowerInvariant()
        };
    }

    /// <summary>
    /// Reverses <see cref="Encrypt"/>, and translates the failure.
    /// </summary>
    /// <remarks>
    /// GCM cannot tell a wrong key from tampered bytes from mismatched additional
    /// data - all three are a tag that does not verify - so all three become
    /// <see cref="ErrorCodes.BadUserKey"/>, with the platform exception kept as
    /// the inner one.
    /// </remarks>
    internal static string Decrypt(Encrypted record, byte[] key, string aad, string what)
    {
        byte[] iv, tag, data;
        try
        {
            iv = Convert.FromHexString(record.Iv);
            tag = Convert.FromHexString(record.AuthTag);
            data = Convert.FromHexString(record.Data);
        }
        catch (FormatException cause)
        {
            throw new KeystoreException(
                ErrorCodes.StoreCorrupt, $"the encrypted {what} has a malformed hex field", cause);
        }

        if (iv.Length == 0)
        {
            throw new KeystoreException(ErrorCodes.StoreCorrupt, $"the encrypted {what} has an empty iv");
        }

        var associated = aad.Length == 0 ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(aad);
        var plaintext = new byte[data.Length];

        try
        {
            if (iv.Length == Format.IvLength)
            {
                using var gcm = new AesGcm(key, tag.Length);
                gcm.Decrypt(iv, data, tag, plaintext, associated);
            }
            else
            {
                LegacyGcm.Decrypt(key, iv, data, associated, tag, plaintext);
            }
        }
        catch (CryptographicException cause)
        {
            throw new KeystoreException(
                ErrorCodes.BadUserKey,
                $"could not decrypt the {what}: the key is wrong, or the stored bytes have been altered",
                cause);
        }

        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>
    /// A filesystem-safe, collision-resistant filename for a key.
    /// </summary>
    /// <remarks>
    /// The stem is for humans, so it is the key with anything unsafe replaced -
    /// which neutralises "../", drive letters and the characters Windows
    /// refuses. Sanitising alone would map "a/b" and "a_b" onto one file, so the
    /// real identity is the hash suffix; the stem is only a label.
    /// <para>
    /// The stem is truncated by UTF-8 bytes, matching every other implementation.
    /// A multi-byte character straddling the limit is cut, but the name is a
    /// label and the hash is the identity, so a mangled label costs nothing.
    /// </para>
    /// </remarks>
    internal static string SafeFileName(string key)
    {
        var bytes = Encoding.UTF8.GetBytes(key);
        var stem = new StringBuilder();

        for (var i = 0; i < bytes.Length && stem.Length < Format.FilenameStemLimit; i++)
        {
            var c = (char)bytes[i];
            var safe = c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-';
            stem.Append(safe ? c : '_');
        }

        var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        return $"{stem}-{hash[..Format.FilenameHashLength]}{Format.ValueExtension}";
    }
}
