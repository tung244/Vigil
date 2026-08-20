namespace Vigil.Core.Tier1.Sigma;

/// <summary>
/// Loaded set of Sigma rules, evaluated against normalized event field maps.
/// Rules that fail to parse are skipped (their error is surfaced via
/// <see cref="LoadErrors"/>) so one bad file never takes detection down.
/// </summary>
public sealed class SigmaEngine
{
    private readonly List<SigmaRule> _rules;

    private SigmaEngine(List<SigmaRule> rules, List<string> loadErrors)
    {
        _rules = rules;
        LoadErrors = loadErrors;
    }

    public int RuleCount => _rules.Count;

    public IReadOnlyList<string> LoadErrors { get; }

    /// <summary>An engine with no rules — matching always returns empty.</summary>
    public static SigmaEngine Empty { get; } = new([], []);

    /// <summary>
    /// Shared instance for the pipeline: loads once from $VIGIL_RULES_DIR or
    /// &lt;AppContext.BaseDirectory&gt;/rules. Missing directory = empty engine
    /// (unit tests construct their own engines with explicit paths).
    /// </summary>
    public static SigmaEngine Default => _default.Value;

    private static readonly Lazy<SigmaEngine> _default = new(() =>
    {
        var dir = Environment.GetEnvironmentVariable("VIGIL_RULES_DIR")
            ?? Path.Combine(AppContext.BaseDirectory, "rules");
        return Directory.Exists(dir) ? LoadFromDirectory(dir) : Empty;
    });

    public static SigmaEngine LoadFromDirectory(string directory)
    {
        var rules = new List<SigmaRule>();
        var errors = new List<string>();

        foreach (var file in Directory.EnumerateFiles(directory, "*.yml", SearchOption.AllDirectories)
                     .Concat(Directory.EnumerateFiles(directory, "*.yaml", SearchOption.AllDirectories))
                     .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                rules.Add(SigmaYamlParser.Parse(File.ReadAllText(file)));
            }
            catch (Exception ex) when (ex is FormatException or YamlDotNet.Core.YamlException or IOException)
            {
                errors.Add($"{Path.GetFileName(file)}: {ex.Message}");
            }
        }

        return new SigmaEngine(rules, errors);
    }

    /// <summary>Rules whose condition holds for this single event.</summary>
    public IReadOnlyList<SigmaRule> Evaluate(IReadOnlyDictionary<string, string> evt)
    {
        var matched = new List<SigmaRule>();
        foreach (var rule in _rules)
        {
            var selectionResults = new Dictionary<string, bool>(StringComparer.Ordinal);
            bool ResultFor(string name) =>
                selectionResults.TryGetValue(name, out var cached)
                    ? cached
                    : selectionResults[name] = rule.Selections[name].Matches(evt);

            try
            {
                if (rule.Condition.Evaluate(ResultFor))
                {
                    matched.Add(rule);
                }
            }
            catch (KeyNotFoundException)
            {
                // Condition referenced a selection that does not exist — should
                // have been caught at load time; treat as no match.
            }
        }

        return matched;
    }

    /// <summary>Distinct matching rules across a batch of events, with hit counts.</summary>
    public IReadOnlyList<(SigmaRule Rule, int Hits)> EvaluateBatch(
        IEnumerable<IReadOnlyDictionary<string, string>> events)
    {
        var hits = new Dictionary<SigmaRule, int>();
        foreach (var evt in events)
        {
            foreach (var rule in Evaluate(evt))
            {
                hits[rule] = hits.TryGetValue(rule, out var count) ? count + 1 : 1;
            }
        }

        return hits.Select(kv => (kv.Key, kv.Value))
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Key.Title, StringComparer.Ordinal)
            .ToList();
    }
}
