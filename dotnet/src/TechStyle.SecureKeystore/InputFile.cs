using System.Text.Json;

namespace TechStyle.SecureKeystore;

/// <summary>One of the three shapes an input file can take.</summary>
public enum InputFormat
{
    /// <summary><c>master:&lt;key&gt;</c> on the first line, then <c>key:value</c> lines.</summary>
    Colon,

    /// <summary>dotenv: <c>KEY=value</c>, with comments, quotes and <c>export</c>.</summary>
    Env,

    /// <summary>A flat object with a "master" property.</summary>
    Json
}

/// <summary>One key-value pair read out of an input file.</summary>
/// <param name="Key">The key name.</param>
/// <param name="Value">Its value, always as a string.</param>
public sealed record InputEntry(string Key, string Value);

/// <summary>What an input file said.</summary>
/// <param name="MasterKey">The master key, or null if the file did not define one.</param>
/// <param name="Entries">Everything else, in the order the file gave it.</param>
public sealed record ParsedInput(string? MasterKey, IReadOnlyList<InputEntry> Entries);

/// <summary>
/// Reading an input file into a master key and a list of entries.
/// </summary>
/// <remarks>
/// Three formats, chosen by extension, all saying the same thing. They are
/// parsed here rather than in the store so that each can be tested against a
/// string, with no directory involved.
/// </remarks>
public static class InputFile
{
    /// <summary>
    /// The format an input file will be read as, from its extension. ".json" and
    /// ".env" are named; everything else is the colon format.
    /// </summary>
    public static InputFormat FormatFor(string inputFile) =>
        Path.GetExtension(inputFile).ToLowerInvariant() switch
        {
            ".json" => InputFormat.Json,
            ".env" => InputFormat.Env,
            _ => InputFormat.Colon
        };

    /// <summary>Reads a file and parses it as whatever its extension says it is.</summary>
    public static ParsedInput Parse(string inputFile)
    {
        string content;
        try
        {
            content = File.ReadAllText(inputFile);
        }
        catch (Exception cause) when (cause is IOException or UnauthorizedAccessException)
        {
            throw new KeystoreException(ErrorCodes.BadInput, $"could not read input file: {inputFile}", cause);
        }

        return ParseText(content, FormatFor(inputFile));
    }

    /// <summary>Parses input text in a named format. The file-free half of <see cref="Parse"/>.</summary>
    public static ParsedInput ParseText(string content, InputFormat format) => format switch
    {
        InputFormat.Json => ParseJson(content),
        InputFormat.Env => ParseEnv(content),
        InputFormat.Colon => ParseColon(content),
        _ => throw new KeystoreException(ErrorCodes.BadInput, $"unknown input format: {format}")
    };

    /// <summary>
    /// The default format: <c>master:&lt;key&gt;</c> first, then <c>key:value</c>.
    /// </summary>
    /// <remarks>
    /// Only the first colon splits, so a value may contain as many more as it
    /// likes - which is what lets a URL or a connection string go in without
    /// escaping.
    /// </remarks>
    private static ParsedInput ParseColon(string content)
    {
        var lines = content
            .Split('\n')
            .Select(line => line.Trim())
            .Where(line => line.Length > 0)
            .ToList();

        if (lines.Count == 0)
        {
            throw new KeystoreException(ErrorCodes.BadInput, "input file is empty");
        }

        var separator = lines[0].IndexOf(':');
        if (separator < 0 || lines[0][..separator] != Format.MasterEntryKey)
        {
            throw new KeystoreException(
                ErrorCodes.BadInput, $"first line must be \"{Format.MasterEntryKey}:your_master_key\"");
        }

        var masterKey = lines[0][(separator + 1)..];
        var entries = new List<InputEntry>();

        foreach (var line in lines.Skip(1))
        {
            var split = line.IndexOf(':');
            if (split < 0)
            {
                continue;
            }
            entries.Add(new InputEntry(line[..split], line[(split + 1)..]));
        }

        return new ParsedInput(masterKey, entries);
    }

    /// <summary>
    /// dotenv syntax.
    /// </summary>
    /// <remarks>
    /// Lines beginning "#" are skipped, as are lines with no "=" and lines with
    /// an empty key. A leading "export " is stripped. A matched pair of single
    /// or double quotes around the whole value is stripped - no escape sequences
    /// are interpreted. The master entry may appear anywhere.
    /// </remarks>
    private static ParsedInput ParseEnv(string content)
    {
        string? masterKey = null;
        var entries = new List<InputEntry>();

        foreach (var raw in content.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (line.StartsWith("export ", StringComparison.Ordinal))
            {
                line = line["export ".Length..].Trim();
            }

            var equals = line.IndexOf('=');
            if (equals < 0)
            {
                continue;
            }

            var key = line[..equals].Trim();
            if (key.Length == 0)
            {
                continue;
            }

            var value = line[(equals + 1)..].Trim();
            if (value.Length >= 2 &&
                ((value[0] == '"' && value[^1] == '"') || (value[0] == '\'' && value[^1] == '\'')))
            {
                value = value[1..^1];
            }

            if (key == Format.MasterEntryKey)
            {
                masterKey = value;
                continue;
            }

            entries.Add(new InputEntry(key, value));
        }

        return new ParsedInput(masterKey, entries);
    }

    /// <summary>
    /// A flat object.
    /// </summary>
    /// <remarks>
    /// Values that are not strings are serialised to their JSON form rather than
    /// refused, so a port number or a feature flag lifted straight out of an
    /// existing config file goes in without being quoted first. Everything comes
    /// back out as a string, which is what the store holds.
    /// </remarks>
    private static ParsedInput ParseJson(string content)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(content);
        }
        catch (JsonException cause)
        {
            throw new KeystoreException(ErrorCodes.BadInput, "invalid JSON input file", cause);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new KeystoreException(ErrorCodes.BadInput, "JSON input must be an object of key-value pairs");
            }

            string? masterKey = null;
            var entries = new List<InputEntry>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var text = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? ""
                    : property.Value.GetRawText();

                if (property.Name == Format.MasterEntryKey)
                {
                    masterKey = text;
                    continue;
                }

                entries.Add(new InputEntry(property.Name, text));
            }

            return new ParsedInput(masterKey, entries);
        }
    }
}
