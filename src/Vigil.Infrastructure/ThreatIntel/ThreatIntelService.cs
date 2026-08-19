using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;
using Vigil.Core.ThreatIntel;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// Cache-first threat intel enrichment. For each applicable source the
/// <c>threat_intel_results</c> table acts as a cache: a row matching
/// (Ioc.Type, Ioc.Value, Source) with LookedUpAt within CacheHours is reused
/// as-is (including its original FromLiveApi flag). On a miss the live client
/// runs; any failure (missing key, 429, timeout, network) degrades to the
/// heuristic fallback with a <c>{"fallback": true, ...}</c> raw payload.
/// </summary>
public sealed class ThreatIntelService(
    VigilDbContext db,
    VirusTotalClient virusTotal,
    AbuseIpDbClient abuseIpDb,
    ThreatIntelOptions options,
    ILogger<ThreatIntelService> logger) : IThreatIntelService
{
    public async Task<IReadOnlyList<ThreatIntelResult>> LookupAsync(
        IocType type,
        string value,
        Guid jobId,
        IocExtractor extractedBy = IocExtractor.Rule,
        CancellationToken cancellationToken = default)
    {
        var sources = ApplicableSources(type);
        if (sources.Count == 0)
            return [];

        var cutoff = DateTimeOffset.UtcNow.AddHours(-options.CacheHours);
        var results = new List<ThreatIntelResult>(sources.Count);

        foreach (var source in sources)
        {
            var cached = await db.ThreatIntelResults
                .Where(r => r.Source == source
                            && r.LookedUpAt > cutoff
                            && r.Ioc.Type == type
                            && r.Ioc.Value == value)
                .OrderByDescending(r => r.LookedUpAt)
                .FirstOrDefaultAsync(cancellationToken);

            if (cached is not null)
            {
                results.Add(cached);
                continue;
            }

            var lookup = source == ThreatIntelSource.VirusTotal
                ? await virusTotal.LookupAsync(type, value, cancellationToken)
                : await abuseIpDb.LookupAsync(type, value, cancellationToken);

            var row = lookup.Success
                ? new ThreatIntelResult
                {
                    Id = Guid.NewGuid(),
                    Source = source,
                    RawResponse = lookup.RawJson,
                    MaliciousScore = lookup.Score,
                    FromLiveApi = true,
                    LookedUpAt = DateTimeOffset.UtcNow
                }
                : BuildFallbackResult(source, type, value, lookup.FailureReason ?? "unknown");

            row.Ioc = await FindOrCreateIocAsync(type, value, jobId, extractedBy, cancellationToken);
            row.IocId = row.Ioc.Id;

            db.ThreatIntelResults.Add(row);
            await db.SaveChangesAsync(cancellationToken);
            results.Add(row);
        }

        return results;
    }

    private static List<ThreatIntelSource> ApplicableSources(IocType type) => type switch
    {
        IocType.Ip => [ThreatIntelSource.VirusTotal, ThreatIntelSource.AbuseIpDb],
        IocType.Domain or IocType.Url or IocType.Hash => [ThreatIntelSource.VirusTotal],
        _ => [] // Email: no applicable source yet
    };

    private ThreatIntelResult BuildFallbackResult(
        ThreatIntelSource source, IocType type, string value, string reason)
    {
        var heuristic = ThreatIntelHeuristics.Score(type, value);
        logger.LogWarning(
            "Threat intel fallback for {Type} {Value} via {Source}: {Reason} (heuristic score {Score})",
            type, value, source, reason, heuristic.Score);

        return new ThreatIntelResult
        {
            Id = Guid.NewGuid(),
            Source = source,
            RawResponse = JsonSerializer.Serialize(new
            {
                fallback = true,
                source = source.ToString(),
                ioc = value,
                reason,
                heuristic_score = heuristic.Score,
                flags = heuristic.Flags
            }),
            MaliciousScore = heuristic.Score,
            FromLiveApi = false,
            LookedUpAt = DateTimeOffset.UtcNow
        };
    }

    private async Task<Ioc> FindOrCreateIocAsync(
        IocType type, string value, Guid jobId, IocExtractor extractedBy, CancellationToken cancellationToken)
    {
        var ioc = await db.Iocs.FirstOrDefaultAsync(
            i => i.JobId == jobId && i.Type == type && i.Value == value, cancellationToken);
        if (ioc is not null)
            return ioc;

        ioc = new Ioc
        {
            Id = Guid.NewGuid(),
            JobId = jobId,
            Type = type,
            Value = value,
            ExtractedBy = extractedBy
        };
        db.Iocs.Add(ioc);
        return ioc;
    }
}
