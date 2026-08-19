using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;
using Vigil.Core.ThreatIntel;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.Tier2;

/// <summary>
/// Enriches every IOC of a job via <see cref="IThreatIntelService"/> (cache →
/// live API → heuristic fallback). Pure tool calls, no LLM — same as the old
/// system, where the threat intel agent's LLM only summarized afterwards.
/// </summary>
public sealed class ThreatIntelStage(
    VigilDbContext db,
    IThreatIntelService threatIntel,
    ILogger<ThreatIntelStage> logger)
{
    /// <summary>Returns the number of threat intel results produced/reused.</summary>
    public async Task<int> EnrichAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        var iocs = await db.Iocs.Where(i => i.JobId == jobId).ToListAsync(cancellationToken);
        var resultCount = 0;

        foreach (var ioc in iocs)
        {
            var results = await threatIntel.LookupAsync(
                ioc.Type, ioc.Value, jobId, ioc.ExtractedBy, cancellationToken);
            resultCount += results.Count;
        }

        logger.LogInformation("Threat intel enrichment for job {JobId}: {IocCount} IOCs, {ResultCount} results",
            jobId, iocs.Count, resultCount);
        return resultCount;
    }
}

/// <summary>
/// Materializes the entities Tier 1 rules already extracted (stored in
/// <c>tier1_results.rule_check_results.extracted</c>) as <see cref="Ioc"/>
/// rows with <see cref="IocExtractor.Rule"/>. Idempotent: existing rows with
/// the same (Type, Value) are left untouched, so LLM-extracted duplicates are
/// also prevented downstream.
/// </summary>
internal static class RuleIocSeeder
{
    /// <summary>The parts of the stored Tier 1 rule report Tier 2 cares about.</summary>
    public sealed record Tier1RuleData(
        IReadOnlyList<string> MatchedRules,
        JsonElement Extracted,
        int RiskScore);

    /// <summary>Reads the stored rule report; null when the payload is corrupt.</summary>
    public static Tier1RuleData? TryReadReport(string ruleCheckResultsJson)
    {
        try
        {
            using var document = JsonDocument.Parse(ruleCheckResultsJson);
            var root = document.RootElement;

            var matchedRules = root.TryGetProperty("matchedRules", out var rules)
                               && rules.ValueKind == JsonValueKind.Array
                ? rules.EnumerateArray()
                    .Where(e => e.ValueKind == JsonValueKind.String)
                    .Select(e => e.GetString()!)
                    .ToList()
                : [];

            // Clone: the JsonDocument is disposed on return.
            var extracted = root.TryGetProperty("extracted", out var extractedElement)
                ? extractedElement.Clone()
                : (JsonElement?)null;

            var riskScore = root.TryGetProperty("riskScore", out var scoreElement)
                            && scoreElement.ValueKind == JsonValueKind.Number
                            && scoreElement.TryGetInt32(out var score)
                ? score
                : 0;

            return extracted is null ? null : new Tier1RuleData(matchedRules, extracted.Value, riskScore);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static async Task<int> SeedAsync(
        VigilDbContext db, Guid jobId, Tier1RuleData report, CancellationToken cancellationToken)
    {
        var candidates = ExtractCandidates(report.Extracted)
            .DistinctBy(c => (c.Type, Value: c.Value.ToLowerInvariant()))
            .ToList();
        if (candidates.Count == 0)
        {
            return 0;
        }

        var existing = await db.Iocs.Where(i => i.JobId == jobId)
            .Select(i => new { i.Type, i.Value })
            .ToListAsync(cancellationToken);
        var existingKeys = existing
            .Select(e => (e.Type, Value: e.Value.ToLowerInvariant()))
            .ToHashSet();

        var added = 0;
        foreach (var (type, value) in candidates)
        {
            if (existingKeys.Add((type, value.ToLowerInvariant())))
            {
                db.Iocs.Add(new Ioc
                {
                    Id = Guid.NewGuid(),
                    JobId = jobId,
                    Type = type,
                    Value = value,
                    ExtractedBy = IocExtractor.Rule
                });
                added++;
            }
        }
        return added;
    }

    private static IEnumerable<(IocType Type, string Value)> ExtractCandidates(JsonElement extracted)
    {
        foreach (var url in ReadStringList(extracted, "urls"))
        {
            yield return (IocType.Url, url);
        }
        foreach (var domain in ReadStringList(extracted, "domains"))
        {
            yield return (IocType.Domain, domain);
        }
        foreach (var ip in ReadStringList(extracted, "ips").Concat(ReadStringList(extracted, "headerIps"))
                     .Concat(ReadStringList(extracted, "uniqueIps")))
        {
            yield return (IocType.Ip, ip);
        }
        if (extracted.TryGetProperty("sender", out var sender)
            && sender.ValueKind == JsonValueKind.String
            && sender.GetString() is { Length: > 0 } senderValue)
        {
            yield return (IocType.Email, senderValue);
        }
    }

    private static IEnumerable<string> ReadStringList(JsonElement extracted, string key) =>
        extracted.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .Where(s => !string.IsNullOrWhiteSpace(s))
            : [];
}
