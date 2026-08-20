namespace Vigil.Core.Tier1.Sigma;

/// <summary>
/// One parsed Sigma rule (subset — see SigmaYamlParser). Selections are
/// evaluated per event; the condition expression combines them.
/// </summary>
public sealed class SigmaRule
{
    public required string Title { get; init; }
    public string Id { get; init; } = string.Empty;
    public string Level { get; init; } = "informational";
    public string Description { get; init; } = string.Empty;

    /// <summary>selection name → matcher (null = the special "keywords" form, unsupported).</summary>
    public Dictionary<string, SigmaSelection> Selections { get; } = new(StringComparer.Ordinal);

    /// <summary>Parsed at load time, after selections are known.</summary>
    public SigmaConditionExpression Condition { get; set; } = null!;

    /// <summary>Stable slug for evidence trails, e.g. "aws_root_account_usage".</summary>
    public string Slug
    {
        get
        {
            var chars = Title.Trim().ToLowerInvariant()
                .Select(c => char.IsLetterOrDigit(c) ? c : '_')
                .ToArray();
            var slug = new string(chars);
            while (slug.Contains("__", StringComparison.Ordinal))
            {
                slug = slug.Replace("__", "_", StringComparison.Ordinal);
            }

            return slug.Trim('_');
        }
    }
}

/// <summary>A named selection: field criteria ANDed together.</summary>
public sealed class SigmaSelection
{
    public required string Name { get; init; }
    public List<SigmaFieldMatcher> Matchers { get; } = [];

    public bool Matches(IReadOnlyDictionary<string, string> evt) =>
        Matchers.All(m => m.Matches(evt));
}

/// <summary>
/// One field criterion: normalized field name + values ORed, each value
/// checked with the given modifier. Sigma values support * and ? wildcards.
/// </summary>
public sealed class SigmaFieldMatcher
{
    public required string Field { get; init; }
    public required SigmaModifier Modifier { get; init; }
    public required List<string> Values { get; init; }

    public bool Matches(IReadOnlyDictionary<string, string> evt)
    {
        if (!evt.TryGetValue(Field, out var actual) || actual.Length == 0)
        {
            return false; // missing field never matches
        }

        return Values.Any(v => MatchesValue(actual, v));
    }

    private bool MatchesValue(string actual, string expected)
    {
        // Wildcards override the modifier semantics (Sigma: modifiers apply,
        // then wildcards are resolved within that comparison).
        if (expected.Contains('*') || expected.Contains('?'))
        {
            return WildcardMatch(actual, expected);
        }

        return Modifier switch
        {
            SigmaModifier.Contains => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            SigmaModifier.StartsWith => actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase),
            SigmaModifier.EndsWith => actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase),
            _ => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
        };
    }

    /// <summary>Case-insensitive glob: * = any run, ? = single char.</summary>
    private static bool WildcardMatch(string actual, string pattern)
    {
        var a = 0;
        var p = 0;
        var starIndex = -1;
        var starCheckpoint = 0;

        while (a < actual.Length)
        {
            if (p < pattern.Length
                && (pattern[p] == '?'
                    || char.ToLowerInvariant(pattern[p]) == char.ToLowerInvariant(actual[a])))
            {
                a++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                starIndex = p++;
                starCheckpoint = a;
            }
            else if (starIndex >= 0)
            {
                p = starIndex + 1;
                a = ++starCheckpoint;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }
}

public enum SigmaModifier
{
    Exact,
    Contains,
    StartsWith,
    EndsWith
}
