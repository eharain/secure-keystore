using System.Security.Cryptography;

namespace TechStyle.SecureKeystore;

/// <summary>
/// AES-GCM for the one nonce length .NET will not do.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="AesGcm"/> reports <c>NonceByteSizes</c> as 12 to 12 and throws on
/// anything else. Format 2.0 of this store used a 16-byte IV, so a 2.0 store -
/// which every implementation must still be able to read - is unreachable
/// through the platform type. This class covers exactly that gap and nothing
/// else: <see cref="Crypto"/> routes 12-byte work to <see cref="AesGcm"/> and
/// only falls back here.
/// </para>
/// <para>
/// This is NIST SP 800-38D as written, with no cleverness: H is AES over a zero
/// block, J0 comes from GHASH when the nonce is not 96 bits, the data goes
/// through CTR, and the tag is GHASH over the lengths XOR the encryption of J0.
/// The bit-by-bit field multiplication is the slow one on purpose - it is data
/// independent, and it runs only on legacy records.
/// </para>
/// <para>
/// Hand-written cipher modes deserve suspicion, so this one is held to two
/// independent checks: it must agree with <see cref="AesGcm"/> byte for byte on
/// 12-byte nonces, where both can run, and it must decrypt the format 2.0
/// fixtures in the shared conformance corpus - bytes produced by the JavaScript
/// implementation, which has never seen this code.
/// </para>
/// <para>
/// Format 3.0 uses a 12-byte IV precisely so that no implementation needs any of
/// this. It exists to read the past, not to extend it.
/// </para>
/// </remarks>
internal static class LegacyGcm
{
    private const int BlockSize = 16;

    /// <summary>The GF(2^128) reduction polynomial, in the bit order GCM uses.</summary>
    private const byte ReductionByte = 0xE1;

    /// <summary>Encrypts and produces the tag, for any nonce length.</summary>
    internal static void Encrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        using var aes = CreateAes(key);

        var h = new byte[BlockSize];
        EncryptBlock(aes, h, h);

        var j0 = ComputeJ0(aes, h, nonce);

        var counter = (byte[])j0.Clone();
        Increment32(counter);
        Gctr(aes, counter, plaintext, ciphertext);

        ComputeTag(aes, h, j0, associatedData, ciphertext, tag);
    }

    /// <summary>
    /// Verifies the tag and decrypts, for any nonce length.
    /// </summary>
    /// <exception cref="AuthenticationTagMismatchException">
    /// If the tag does not verify. Nothing is written to <paramref name="plaintext"/>
    /// in that case - a caller must never see unauthenticated bytes.
    /// </exception>
    internal static void Decrypt(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        using var aes = CreateAes(key);

        var h = new byte[BlockSize];
        EncryptBlock(aes, h, h);

        var j0 = ComputeJ0(aes, h, nonce);

        // The tag is computed over the ciphertext, so it is checked before a
        // single byte is decrypted.
        Span<byte> expected = stackalloc byte[BlockSize];
        ComputeTag(aes, h, j0, associatedData, ciphertext, expected);

        if (!CryptographicOperations.FixedTimeEquals(expected[..tag.Length], tag))
        {
            throw new AuthenticationTagMismatchException();
        }

        var counter = (byte[])j0.Clone();
        Increment32(counter);
        Gctr(aes, counter, ciphertext, plaintext);
    }

    private static Aes CreateAes(byte[] key)
    {
        var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    /// <summary>One raw AES block. GCM is built entirely out of this.</summary>
    private static void EncryptBlock(Aes aes, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> buffer = stackalloc byte[BlockSize];
        input.CopyTo(buffer);
        aes.EncryptEcb(buffer, output, PaddingMode.None);
    }

    /// <summary>
    /// The pre-counter block.
    /// </summary>
    /// <remarks>
    /// A 96-bit nonce is used directly with a counter of 1 appended - the common
    /// case, and the only one <see cref="AesGcm"/> supports. Any other length is
    /// hashed: J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64). For the 16-byte
    /// nonce this class exists for, that is exactly two blocks.
    /// </remarks>
    private static byte[] ComputeJ0(Aes aes, byte[] h, byte[] nonce)
    {
        if (nonce.Length == 12)
        {
            var j0 = new byte[BlockSize];
            nonce.CopyTo(j0, 0);
            j0[15] = 1;
            return j0;
        }

        var ghash = new byte[BlockSize];

        var whole = nonce.Length / BlockSize * BlockSize;
        for (var offset = 0; offset < whole; offset += BlockSize)
        {
            XorInto(ghash, nonce.AsSpan(offset, BlockSize));
            MultiplyByH(ghash, h);
        }

        if (whole < nonce.Length)
        {
            Span<byte> partial = stackalloc byte[BlockSize];
            nonce.AsSpan(whole).CopyTo(partial);
            XorInto(ghash, partial);
            MultiplyByH(ghash, h);
        }

        // The length block: 64 zero bits, then the nonce length in bits.
        Span<byte> lengths = stackalloc byte[BlockSize];
        WriteUInt64BigEndian(lengths[8..], (ulong)nonce.Length * 8);
        XorInto(ghash, lengths);
        MultiplyByH(ghash, h);

        return ghash;
    }

    /// <summary>GCTR: counter mode over the AES block function.</summary>
    private static void Gctr(Aes aes, byte[] counter, ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> keystream = stackalloc byte[BlockSize];

        for (var offset = 0; offset < input.Length; offset += BlockSize)
        {
            EncryptBlock(aes, counter, keystream);
            Increment32(counter);

            var take = Math.Min(BlockSize, input.Length - offset);
            for (var i = 0; i < take; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
            }
        }
    }

    /// <summary>
    /// The authentication tag: GHASH over the associated data, the ciphertext
    /// and their lengths, encrypted under J0.
    /// </summary>
    private static void ComputeTag(
        Aes aes,
        byte[] h,
        byte[] j0,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> tag)
    {
        var ghash = new byte[BlockSize];

        GhashPadded(ghash, h, associatedData);
        GhashPadded(ghash, h, ciphertext);

        Span<byte> lengths = stackalloc byte[BlockSize];
        WriteUInt64BigEndian(lengths[..8], (ulong)associatedData.Length * 8);
        WriteUInt64BigEndian(lengths[8..], (ulong)ciphertext.Length * 8);
        XorInto(ghash, lengths);
        MultiplyByH(ghash, h);

        Span<byte> masked = stackalloc byte[BlockSize];
        EncryptBlock(aes, j0, masked);

        for (var i = 0; i < BlockSize; i++)
        {
            tag[i] = (byte)(ghash[i] ^ masked[i]);
        }
    }

    /// <summary>GHASH over a span, zero-padded to a block boundary.</summary>
    private static void GhashPadded(byte[] ghash, byte[] h, ReadOnlySpan<byte> data)
    {
        var whole = data.Length / BlockSize * BlockSize;

        for (var offset = 0; offset < whole; offset += BlockSize)
        {
            XorInto(ghash, data.Slice(offset, BlockSize));
            MultiplyByH(ghash, h);
        }

        if (whole < data.Length)
        {
            Span<byte> partial = stackalloc byte[BlockSize];
            data[whole..].CopyTo(partial);
            XorInto(ghash, partial);
            MultiplyByH(ghash, h);
        }
    }

    /// <summary>
    /// Multiplication in GF(2^128), the field GCM is defined over.
    /// </summary>
    /// <remarks>
    /// Bit by bit, most significant first, with the reduction applied whenever a
    /// one falls off the bottom. The loop is fixed-length and its branches
    /// depend only on the key-derived <paramref name="h"/> and on the data
    /// already public in the ciphertext, never on plaintext.
    /// </remarks>
    private static void MultiplyByH(byte[] x, byte[] h)
    {
        Span<byte> z = stackalloc byte[BlockSize];
        Span<byte> v = stackalloc byte[BlockSize];
        h.CopyTo(v);

        for (var bit = 0; bit < 128; bit++)
        {
            var set = (x[bit >> 3] >> (7 - (bit & 7))) & 1;
            if (set == 1)
            {
                for (var i = 0; i < BlockSize; i++)
                {
                    z[i] ^= v[i];
                }
            }

            var carry = v[BlockSize - 1] & 1;
            ShiftRightOne(v);
            if (carry == 1)
            {
                v[0] ^= ReductionByte;
            }
        }

        z.CopyTo(x);
    }

    private static void ShiftRightOne(Span<byte> value)
    {
        for (var i = BlockSize - 1; i > 0; i--)
        {
            value[i] = (byte)((value[i] >> 1) | ((value[i - 1] & 1) << 7));
        }
        value[0] >>= 1;
    }

    private static void XorInto(byte[] target, ReadOnlySpan<byte> source)
    {
        for (var i = 0; i < BlockSize; i++)
        {
            target[i] ^= source[i];
        }
    }

    /// <summary>Increments the rightmost 32 bits, which is what GCM counts with.</summary>
    private static void Increment32(byte[] counter)
    {
        for (var i = BlockSize - 1; i >= BlockSize - 4; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

    private static void WriteUInt64BigEndian(Span<byte> destination, ulong value)
    {
        for (var i = 7; i >= 0; i--)
        {
            destination[i] = (byte)value;
            value >>= 8;
        }
    }
}
