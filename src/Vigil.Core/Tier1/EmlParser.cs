using System.Text.RegularExpressions;

namespace Vigil.Core.Tier1;

/// <summary>A minimally parsed .eml message: unfolded headers plus raw body text.</summary>
public sealed class EmlMessage
{
    /// <summary>All headers in order of appearance (may contain duplicates, e.g. Received).</summary>
    public required IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; }

    /// <summary>Everything after the first blank line; empty when the message has no body.</summary>
    public required string Body { get; init; }

    public string? Subject => GetHeader("Subject");

    public string? From => GetHeader("From");

    /// <summary>First value of a header, or null when absent. Names are case-insensitive.</summary>
    public string? GetHeader(string name) =>
        Headers.FirstOrDefault(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            is { Key: not null } pair
            ? pair.Value
            : null;

    /// <summary>All values of a (possibly repeated) header. Names are case-insensitive.</summary>
    public IEnumerable<string> GetHeaders(string name) =>
        Headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value);
}

/// <summary>
/// Hand-rolled .eml parser for Tier 1: unfolds continuation lines and splits
/// headers from the body at the first blank line. Deliberately does not decode
/// MIME parts — the rule checks scan raw text, exactly like the Python version.
/// </summary>
public static partial class EmlParser
{
    public static EmlMessage Parse(string rawEml)
    {
        var text = rawEml.Replace("\r\n", "\n", StringComparison.Ordinal);
        var headerEnd = text.IndexOf("\n\n", StringComparison.Ordinal);
        var headerBlock = headerEnd >= 0 ? text[..headerEnd] : text;
        var body = headerEnd >= 0 ? text[(headerEnd + 2)..] : string.Empty;

        var headers = new List<KeyValuePair<string, string>>();
        string? currentName = null;
        var currentValue = new System.Text.StringBuilder();

        void Flush()
        {
            if (currentName is not null)
            {
                headers.Add(new(currentName, currentValue.ToString()));
            }
        }

        foreach (var line in headerBlock.Split('\n'))
        {
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t'))
            {
                // Continuation of the previous header.
                if (currentName is not null)
                {
                    currentValue.Append(' ').Append(line.Trim());
                }

                continue;
            }

            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue; // malformed line; ignore
            }

            Flush();
            currentName = line[..colon].Trim();
            currentValue.Clear().Append(line[(colon + 1)..].Trim());
        }

        Flush();

        return new EmlMessage { Headers = headers, Body = body };
    }

    /// <summary>
    /// Parses the Authentication-Results header into { "spf" => "fail", ... }.
    /// Returns an empty dictionary when the header is absent.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ParseAuthenticationResults(EmlMessage message)
    {
        var results = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var header = message.GetHeader("Authentication-Results");
        if (header is null)
        {
            return results;
        }

        foreach (Match match in AuthResultRegex().Matches(header))
        {
            // First occurrence wins; later mta entries repeat the same keys.
            results.TryAdd(match.Groups[1].Value.ToLowerInvariant(), match.Groups[2].Value.ToLowerInvariant());
        }

        return results;
    }

    [GeneratedRegex(@"\b(spf|dkim|dmarc)=(\w+)", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex AuthResultRegex();
}
