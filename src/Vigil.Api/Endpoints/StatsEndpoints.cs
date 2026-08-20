using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Vigil.Api.Contracts;
using Vigil.Core.Domain;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Api.Endpoints;

public static class StatsEndpoints
{
    public static IEndpointRouteBuilder MapStatsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/stats").WithTags("Stats").RequireAuthorization();

        group.MapGet("/", GetStats);
        group.MapGet("/mitre", GetMitreHeatmap);

        return app;
    }

    private static async Task<IResult> GetStats(VigilDbContext db, CancellationToken cancellationToken)
    {
        var totalJobs = await db.AnalysisJobs.CountAsync(cancellationToken);
        var totalReports = await db.Reports.CountAsync(cancellationToken);

        var statusCounts = await db.AnalysisJobs.AsNoTracking()
            .GroupBy(j => j.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.Status, g => g.Count, cancellationToken);

        var severityCounts = await db.Reports.AsNoTracking()
            .GroupBy(r => r.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.Severity, g => g.Count, cancellationToken);

        var avgRiskScore = await db.Reports.AverageAsync(r => (double?)r.RiskScore, cancellationToken) ?? 0;

        var since = DateTimeOffset.UtcNow.AddHours(-24);
        var last24HJobs = await db.AnalysisJobs.CountAsync(j => j.CreatedAt >= since, cancellationToken);

        int CountOf<TKey>(IReadOnlyDictionary<TKey, int> counts, TKey key) where TKey : notnull =>
            counts.TryGetValue(key, out var count) ? count : 0;

        return Results.Ok(new StatsResponse(
            totalJobs,
            totalReports,
            new JobsByStatusResponse(
                CountOf(statusCounts, JobStatus.Queued),
                CountOf(statusCounts, JobStatus.Filtering),
                CountOf(statusCounts, JobStatus.Analyzing),
                CountOf(statusCounts, JobStatus.Done),
                CountOf(statusCounts, JobStatus.Failed)),
            new ReportsBySeverityResponse(
                CountOf(severityCounts, Severity.Low),
                CountOf(severityCounts, Severity.Medium),
                CountOf(severityCounts, Severity.High),
                CountOf(severityCounts, Severity.Critical)),
            Math.Round(avgRiskScore, 2),
            last24HJobs));
    }

    private static async Task<IResult> GetMitreHeatmap(VigilDbContext db, CancellationToken cancellationToken)
    {
        // MitreTechniques is a jsonb string (e.g. ["T1566.002","T1078"]), so
        // aggregation happens in memory after pulling the raw payloads.
        var payloads = await db.Reports.AsNoTracking()
            .Select(r => r.MitreTechniques)
            .ToListAsync(cancellationToken);

        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var payload in payloads)
        {
            foreach (var techniqueId in ParseTechniques(payload))
            {
                counts[techniqueId] = counts.TryGetValue(techniqueId, out var count) ? count + 1 : 1;
            }
        }

        var techniques = counts
            .Select(kv => new MitreTechniqueStat(kv.Key, MitreTacticMap.GetTactic(kv.Key), kv.Value))
            .OrderByDescending(t => t.Count)
            .ThenBy(t => t.TechniqueId, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var presentTactics = techniques.Select(t => t.Tactic).ToHashSet();
        var tactics = MitreTacticMap.TacticOrder.Where(presentTactics.Contains).ToList();

        return Results.Ok(new MitreHeatmapResponse(techniques, tactics));
    }

    /// <summary>Stored jsonb → technique IDs; corrupt payloads degrade to none.</summary>
    private static IEnumerable<string> ParseTechniques(string json)
    {
        List<string>? ids;
        try
        {
            ids = JsonSerializer.Deserialize<List<string>>(json);
        }
        catch (JsonException)
        {
            yield break;
        }

        foreach (var id in ids ?? [])
        {
            var trimmed = id.Trim();
            if (trimmed.Length > 0)
            {
                yield return trimmed;
            }
        }
    }
}
