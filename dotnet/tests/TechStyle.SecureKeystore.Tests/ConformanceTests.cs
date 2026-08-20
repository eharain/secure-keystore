using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;

namespace TechStyle.SecureKeystore.Tests;

/// <summary>
/// The shared corpus, run against this implementation.
/// </summary>
/// <remarks>
/// The corpus was written by the JavaScript implementation. Nothing here has
/// ever seen that code - this library was written against SPEC.md - so passing
/// this file is the whole cross-language claim, tested rather than asserted.
/// <para>
/// It cannot be a comparison of encoders: every write in this format draws a
/// fresh salt and a fresh IV, so two implementations encrypting the same secret
/// never produce the same bytes. What is pinned is the other direction - these
/// bytes, under this key, must come back as this plaintext - plus the refusals,
/// which matter just as much.
/// </para>
/// <para>
/// The format 2.0 store in the corpus is what proves <see cref="LegacyGcm"/>
/// derives J0 correctly for a 16-byte nonce, which is the one thing the
/// AesGcm cross-check in <see cref="LegacyGcmTests"/> cannot cover.
/// </para>
/// </remarks>
public class ConformanceTests
{
    private sealed record StoreCase(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("keystorePath")] string KeystorePath,
        [property: JsonPropertyName("format")] string Format,
        [property: JsonPropertyName("expected")] Dictionary<string, string> Expected);

    private sealed record TokenCase(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("version")] string? Version,
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("expected")] string Expected);

    private sealed record BundleCase(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("importAs")] string ImportAs,
        [property: JsonPropertyName("expected")] Dictionary<string, string> Expected,
        [property: JsonPropertyName("mustNotCreate")] List<string>? MustNotCreate,
        [property: JsonPropertyName("mustCreateInsideStore")] List<string>? MustCreateInsideStore);

    private sealed record TokenRefusal(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("token")] string Token,
        [property: JsonPropertyName("userKey")] string UserKey,
        [property: JsonPropertyName("code")] string Code);

    private sealed record BundleRefusal(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("path")] string Path,
        [property: JsonPropertyName("code")] string Code,
        [property: JsonPropertyName("note")] string? Note);

    private sealed record StoreRefusal(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("keystorePath")] string KeystorePath,
        [property: JsonPropertyName("store")] string Store,
        [property: JsonPropertyName("code")] string Code,
        [property: JsonPropertyName("note")] string? Note);

    private sealed record Refusals(
        [property: JsonPropertyName("tokens")] List<TokenRefusal> Tokens,
        [property: JsonPropertyName("bundles")] List<BundleRefusal> Bundles,
        [property: JsonPropertyName("stores")] List<StoreRefusal> Stores);

    private sealed record Manifest(
        [property: JsonPropertyName("userKey")] string UserKey,
        [property: JsonPropertyName("masterKey")] string MasterKey,
        [property: JsonPropertyName("iterations")] int Iterations,
        [property: JsonPropertyName("stores")] List<StoreCase> Stores,
        [property: JsonPropertyName("tokens")] List<TokenCase> Tokens,
        [property: JsonPropertyName("bundles")] List<BundleCase> Bundles,
        [property: JsonPropertyName("refusals")] Refusals Refusals);

    /// <summary>
    /// Walks up from the test binary to the repository root, which is wherever
    /// the corpus lives regardless of build configuration.
    /// </summary>
    private static string CorpusDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance")))
            {
                dir = dir.Parent;
            }
            return dir is null ? "" : Path.Combine(dir.FullName, "conformance");
        }
    }

    private static readonly Lazy<Manifest?> Loaded = new(() =>
    {
        var path = Path.Combine(CorpusDir, "manifest.json");
        return File.Exists(path) ? JsonSerializer.Deserialize<Manifest>(File.ReadAllText(path)) : null;
    });

    private static Manifest Corpus =>
        Loaded.Value ?? throw new InvalidOperationException(
            "no conformance corpus - run: node conformance/generate.js");

    private static string Fixture(string relative) =>
        Path.Combine(CorpusDir, "fixtures", relative.Replace('/', Path.DirectorySeparatorChar));

    private static Keystore Reader(string keystorePath) => new(new KeystoreOptions
    {
        KeystoreDir = Fixture(keystorePath),
        CreateDir = false
    });

    private static Keystore Scratch(string dir) => new(new KeystoreOptions
    {
        KeystoreDir = Path.Combine(dir, ".keystore"),
        Iterations = Corpus.Iterations
    });

    [Fact]
    public void EveryStoreDecryptsToTheExpectedValues()
    {
        Assert.NotEmpty(Corpus.Stores);

        foreach (var store in Corpus.Stores)
        {
            var keystore = Reader(store.KeystorePath);

            Assert.Equal(store.Format, keystore.GetStoreInfo(store.Name).Version);

            var values = keystore.GetAll(Corpus.UserKey, store.Name);
            Assert.Equal(store.Expected.Count, values.Count);

            foreach (var (key, expected) in store.Expected)
            {
                Assert.Equal(expected, values[key]);
                // And one at a time, which takes a different path through the code.
                Assert.Equal(expected, keystore.Get(key, Corpus.UserKey, store.Name));
            }
        }
    }

    [Fact]
    public void EveryTokenDecryptsToTheExpectedValue()
    {
        Assert.NotEmpty(Corpus.Tokens);

        foreach (var token in Corpus.Tokens)
        {
            Assert.Equal(token.Expected, ValueToken.Decrypt(token.Token, Corpus.UserKey));

            if (token.Version is null)
            {
                Assert.False(ValueToken.IsEncryptedValue(token.Token));
            }
            else
            {
                Assert.True(ValueToken.IsEncryptedValue(token.Token));
                Assert.Equal(token.Version, ValueToken.TokenVersion(token.Token));
            }
        }
    }

    [Fact]
    public void EveryBundleImportsAndDecrypts()
    {
        foreach (var bundle in Corpus.Bundles)
        {
            var dir = Directory.CreateTempSubdirectory("secure-keystore-conformance-").FullName;
            try
            {
                var keystore = Scratch(dir);
                Assert.Equal(bundle.ImportAs, keystore.ImportStore(Fixture(bundle.Path), bundle.ImportAs));

                var values = keystore.GetAll(Corpus.UserKey, bundle.ImportAs);
                foreach (var (key, expected) in bundle.Expected)
                {
                    Assert.Equal(expected, values[key]);
                }

                // A hostile bundle must land entirely inside the target store.
                foreach (var name in bundle.MustNotCreate ?? [])
                {
                    Assert.False(File.Exists(Path.Combine(dir, name)), $"{name} escaped the keystore");
                    Assert.False(File.Exists(Path.Combine(dir, ".keystore", name)), $"{name} escaped its store");
                }

                foreach (var name in bundle.MustCreateInsideStore ?? [])
                {
                    Assert.True(
                        File.Exists(Path.Combine(dir, ".keystore", bundle.ImportAs, name)),
                        $"{name} should be inside the store");
                }
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public void EveryTokenRefusalIsRefused()
    {
        Assert.NotEmpty(Corpus.Refusals.Tokens);

        foreach (var refusal in Corpus.Refusals.Tokens)
        {
            var error = Assert.Throws<KeystoreException>(
                () => ValueToken.Decrypt(refusal.Token, refusal.UserKey));
            Assert.Equal(refusal.Code, error.Code);
        }
    }

    [Fact]
    public void EveryBundleRefusalIsRefused()
    {
        Assert.NotEmpty(Corpus.Refusals.Bundles);

        var dir = Directory.CreateTempSubdirectory("secure-keystore-conformance-").FullName;
        try
        {
            var keystore = Scratch(dir);

            foreach (var refusal in Corpus.Refusals.Bundles)
            {
                var error = Assert.Throws<KeystoreException>(
                    () => keystore.ImportStore(Fixture(refusal.Path), "target"));
                Assert.Equal(refusal.Code, error.Code);
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void EveryStoreRefusalIsRefused()
    {
        foreach (var refusal in Corpus.Refusals.Stores)
        {
            var error = Assert.Throws<KeystoreException>(
                () => Reader(refusal.KeystorePath).GetStoreInfo(refusal.Store));
            Assert.Equal(refusal.Code, error.Code);
        }
    }

    /// <summary>
    /// The other direction: a store this library wrote, holding the corpus's own
    /// awkward values, read back through this library. The JavaScript and Go
    /// suites do the same, which is what closes the loop.
    /// </summary>
    [Fact]
    public void WritesAStoreThatReadsBack()
    {
        var expected = Corpus.Stores.First(store => store.Name == "basic").Expected;
        var dir = Directory.CreateTempSubdirectory("secure-keystore-crosswrite-").FullName;

        try
        {
            var keystore = Scratch(dir);

            var input = Path.Combine(dir, "dotnet-written.env");
            File.WriteAllText(input, $"master={Corpus.MasterKey}\nplaceholder=x");
            keystore.Secure(input, Corpus.UserKey, "dotnet-written");

            foreach (var (key, value) in expected)
            {
                keystore.Set(key, value, Corpus.UserKey, "dotnet-written");
            }
            keystore.DeleteKey("placeholder", "dotnet-written");

            var values = keystore.GetAll(Corpus.UserKey, "dotnet-written");
            foreach (var (key, want) in expected)
            {
                Assert.Equal(want, values[key]);
            }

            // Leave it where a cross-language check can find it, if asked to.
            var outDir = Environment.GetEnvironmentVariable("SECURE_KEYSTORE_CROSS_WRITE_DIR");
            if (!string.IsNullOrEmpty(outDir))
            {
                keystore.ExportStore("dotnet-written", Path.Combine(outDir, "dotnet-written.skb"));
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    /// <summary>
    /// A format 2.0 store read, then migrated to 3.0, then read again.
    /// </summary>
    /// <remarks>
    /// This is the path that matters most for .NET: reading 2.0 needs
    /// <see cref="LegacyGcm"/>, and migrating is how a caller gets off it and
    /// onto the 12-byte IV that <see cref="System.Security.Cryptography.AesGcm"/>
    /// can handle natively.
    /// </remarks>
    [Fact]
    public void MigratesALegacyStoreOffTheSixteenByteNonce()
    {
        var legacy = Corpus.Stores.First(store => store.Format == "2.0");
        var dir = Directory.CreateTempSubdirectory("secure-keystore-migrate-").FullName;

        try
        {
            // Copy the corpus store, so the fixtures are never written to.
            var source = Fixture($"{legacy.KeystorePath}/{legacy.Name}");
            var target = Path.Combine(dir, ".keystore", legacy.Name);
            Directory.CreateDirectory(target);
            foreach (var file in Directory.GetFiles(source))
            {
                File.Copy(file, Path.Combine(target, Path.GetFileName(file)));
            }

            var keystore = Scratch(dir);
            Assert.Equal("2.0", keystore.GetStoreInfo(legacy.Name).Version);
            Assert.False(keystore.GetStoreInfo(legacy.Name).Current);

            var result = keystore.Migrate(legacy.Name, Corpus.UserKey);
            Assert.Equal("2.0", result.From);
            Assert.Equal(Format.StoreVersion, result.To);

            var values = keystore.GetAll(Corpus.UserKey, legacy.Name);
            foreach (var (key, want) in legacy.Expected)
            {
                Assert.Equal(want, values[key]);
            }

            Assert.True(keystore.GetStoreInfo(legacy.Name).Current);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
