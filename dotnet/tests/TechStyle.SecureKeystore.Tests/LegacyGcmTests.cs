using System.Security.Cryptography;
using System.Text;
using TechStyle.SecureKeystore;
using Xunit;

namespace TechStyle.SecureKeystore.Tests;

/// <summary>
/// The hand-written GCM, held against the platform's.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="LegacyGcm"/> exists because <see cref="AesGcm"/> refuses the
/// 16-byte nonce format 2.0 used. Hand-written cipher modes deserve suspicion,
/// so it is checked where both can run: on a 12-byte nonce the two must agree
/// byte for byte, in both directions, across every shape of input that matters.
/// </para>
/// <para>
/// If this file passes, the field arithmetic, the counter, the padding and the
/// length encoding are all right - none of which is nonce-length specific. What
/// remains specific to the 16-byte case is the J0 derivation, and that is
/// covered by the conformance corpus, whose format 2.0 fixtures were produced by
/// the JavaScript implementation.
/// </para>
/// </remarks>
public class LegacyGcmTests
{
    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    public static TheoryData<int, int, int> Shapes()
    {
        var data = new TheoryData<int, int, int>();

        // plaintext length, associated-data length, key length
        foreach (var keyLength in new[] { 16, 24, 32 })
        {
            foreach (var plaintext in new[] { 0, 1, 15, 16, 17, 31, 32, 33, 64, 1000 })
            {
                foreach (var associated in new[] { 0, 1, 16, 20 })
                {
                    data.Add(plaintext, associated, keyLength);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Shapes))]
    public void MatchesAesGcmOnTwelveByteNonces(int plaintextLength, int associatedLength, int keyLength)
    {
        var key = RandomNumberGenerator.GetBytes(keyLength);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = RandomNumberGenerator.GetBytes(plaintextLength);
        var associated = RandomNumberGenerator.GetBytes(associatedLength);

        var platformCiphertext = new byte[plaintextLength];
        var platformTag = new byte[16];
        using (var gcm = new AesGcm(key, 16))
        {
            gcm.Encrypt(nonce, plaintext, platformCiphertext, platformTag, associated);
        }

        var ownCiphertext = new byte[plaintextLength];
        var ownTag = new byte[16];
        LegacyGcm.Encrypt(key, nonce, plaintext, associated, ownCiphertext, ownTag);

        Assert.Equal(platformCiphertext, ownCiphertext);
        Assert.Equal(platformTag, ownTag);

        // And the other direction: what the platform sealed, this must open.
        var opened = new byte[plaintextLength];
        LegacyGcm.Decrypt(key, nonce, platformCiphertext, associated, platformTag, opened);
        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void RoundTripsSixteenByteNonces()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var plaintext = Bytes("the length AesGcm will not take");
        var associated = Bytes("secure-keystore:v3:value:api_key");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        LegacyGcm.Encrypt(key, nonce, plaintext, associated, ciphertext, tag);

        var opened = new byte[plaintext.Length];
        LegacyGcm.Decrypt(key, nonce, ciphertext, associated, tag, opened);

        Assert.Equal(plaintext, opened);
    }

    [Fact]
    public void RejectsATamperedTag()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var plaintext = Bytes("secret");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        LegacyGcm.Encrypt(key, nonce, plaintext, [], ciphertext, tag);

        tag[0] ^= 0x01;

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            LegacyGcm.Decrypt(key, nonce, ciphertext, [], tag, new byte[plaintext.Length]));
    }

    [Fact]
    public void RejectsTamperedCiphertextAndMismatchedAssociatedData()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var plaintext = Bytes("secret");
        var associated = Bytes("context");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        LegacyGcm.Encrypt(key, nonce, plaintext, associated, ciphertext, tag);

        var tampered = (byte[])ciphertext.Clone();
        tampered[0] ^= 0x01;
        Assert.Throws<AuthenticationTagMismatchException>(() =>
            LegacyGcm.Decrypt(key, nonce, tampered, associated, tag, new byte[plaintext.Length]));

        Assert.Throws<AuthenticationTagMismatchException>(() =>
            LegacyGcm.Decrypt(key, nonce, ciphertext, Bytes("different"), tag, new byte[plaintext.Length]));
    }

    /// <summary>
    /// NIST SP 800-38D test case 6, which is the published vector with a nonce
    /// that is not 96 bits - exactly the path <see cref="AesGcm"/> cannot reach
    /// and this class exists for.
    /// </summary>
    [Fact]
    public void MatchesTheNistVectorForALongNonce()
    {
        var key = Convert.FromHexString("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = Convert.FromHexString(
            "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728" +
            "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b");
        var plaintext = Convert.FromHexString(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        var associated = Convert.FromHexString("feedfacedeadbeeffeedfacedeadbeefabaddad2");

        var expectedCiphertext = Convert.FromHexString(
            "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4" +
            "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f");
        var expectedTag = Convert.FromHexString("a44a8266ee1c8eb0c8b5d4cf5ae9f19a");

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        LegacyGcm.Encrypt(key, nonce, plaintext, associated, ciphertext, tag);

        Assert.Equal(expectedCiphertext, ciphertext);
        Assert.Equal(expectedTag, tag);

        var opened = new byte[plaintext.Length];
        LegacyGcm.Decrypt(key, nonce, expectedCiphertext, associated, expectedTag, opened);
        Assert.Equal(plaintext, opened);
    }
}
