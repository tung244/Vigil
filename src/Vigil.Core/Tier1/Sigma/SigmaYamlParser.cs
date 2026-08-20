using YamlDotNet.RepresentationModel;

namespace Vigil.Core.Tier1.Sigma;

/// <summary>
/// Parses the Sigma rule subset this engine supports:
/// title/id/level/description + detection with map selections
/// (field: value | field: [list] | field|modifier: value) and a condition
/// understood by <see cref="SigmaConditionExpression"/>. Unsupported shapes
/// (keywords selections, aggregations like count() near) throw
/// <see cref="FormatException"/> so the loader can skip the file loudly.
/// </summary>
public static class SigmaYamlParser
{
    public static SigmaRule Parse(string yaml)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            throw new FormatException("Sigma rule has no YAML mapping at the root.");
        }

        var title = Scalar(root, "title") ?? throw new FormatException("Sigma rule is missing 'title'.");
        var detection = Child(root, "detection") as YamlMappingNode
            ?? throw new FormatException($"Sigma rule '{title}' is missing a 'detection' mapping.");

        var conditionText = Scalar(detection, "condition")
            ?? throw new FormatException($"Sigma rule '{title}' is missing 'detection.condition'.");

        var rule = new SigmaRule
        {
            Title = title,
            Id = Scalar(root, "id") ?? string.Empty,
            Level = Scalar(root, "level") ?? "informational",
            Description = Scalar(root, "description") ?? string.Empty
        };

        foreach (var entry in detection.Children)
        {
            var name = (entry.Key as YamlScalarNode)?.Value;
            if (name is null || name is "condition" or "timeframe")
            {
                continue;
            }

            rule.Selections[name] = ParseSelection(name, entry.Value);
        }

        if (rule.Selections.Count == 0)
        {
            throw new FormatException($"Sigma rule '{title}' has no selections.");
        }

        var condition = SigmaConditionExpression.Parse(conditionText);
        // Expand "1 of pattern" / "all of them" against the known selections.
        condition = SigmaConditionExpression.ExpandOfQuantifiers(condition, pattern =>
        {
            if (pattern == "them")
            {
                return rule.Selections.Keys.ToList();
            }

            var prefix = pattern.TrimEnd('*');
            return rule.Selections.Keys
                .Where(k => pattern.EndsWith('*') ? k.StartsWith(prefix, StringComparison.Ordinal) : k == pattern)
                .ToList();
        });

        // Validate: every referenced selection must exist.
        var referenced = new List<string>();
        condition.CollectPatterns(referenced);
        var unknown = referenced.Where(r => !r.Contains(' ') && !rule.Selections.ContainsKey(r)).ToList();
        if (unknown.Count > 0)
        {
            throw new FormatException(
                $"Sigma rule '{title}' condition references unknown selection(s): {string.Join(", ", unknown)}.");
        }

        rule.Condition = condition;
        return rule;
    }

    private static SigmaSelection ParseSelection(string name, YamlNode node)
    {
        var selection = new SigmaSelection { Name = name };

        if (node is not YamlMappingNode map)
        {
            throw new FormatException(
                $"Sigma selection '{name}' is not a field mapping (keywords/list selections are not supported).");
        }

        foreach (var entry in map.Children)
        {
            var rawField = (entry.Key as YamlScalarNode)?.Value
                ?? throw new FormatException($"Sigma selection '{name}' has a non-scalar field name.");

            var (field, modifier) = SplitModifier(rawField);
            var values = entry.Value switch
            {
                YamlScalarNode scalar => [scalar.Value ?? string.Empty],
                YamlSequenceNode sequence => sequence.Children
                    .OfType<YamlScalarNode>()
                    .Select(s => s.Value ?? string.Empty)
                    .ToList(),
                _ => throw new FormatException(
                    $"Sigma field '{rawField}' in selection '{name}' has an unsupported value shape.")
            };

            selection.Matchers.Add(new SigmaFieldMatcher
            {
                Field = SigmaFieldNormalizer.Normalize(field),
                Modifier = modifier,
                Values = values
            });
        }

        return selection;
    }

    private static (string Field, SigmaModifier Modifier) SplitModifier(string rawField)
    {
        var parts = rawField.Split('|', 2, StringSplitOptions.TrimEntries);
        if (parts.Length == 1)
        {
            return (parts[0], SigmaModifier.Exact);
        }

        var modifier = parts[1].ToLowerInvariant() switch
        {
            "contains" => SigmaModifier.Contains,
            "startswith" => SigmaModifier.StartsWith,
            "endswith" => SigmaModifier.EndsWith,
            var other => throw new FormatException($"Unsupported Sigma field modifier '{other}'.")
        };
        return (parts[0], modifier);
    }

    private static string? Scalar(YamlMappingNode node, string key) =>
        Child(node, key) is YamlScalarNode scalar ? scalar.Value : null;

    private static YamlNode? Child(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? value : null;
}
