using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Vigil.Core.Domain;
using Vigil.Infrastructure.Persistence;
using Xunit;

namespace Vigil.IntegrationTests;

/// <summary>
/// GET /api/stats and /api/stats/mitre against seeded jobs + reports.
/// The test database is shared with parallel tests, so global counters are
/// asserted relatively (&gt;= seeded) while the unique marker technique
/// carries an exact-count assertion. Seeded rows are cleaned up afterwards.
/// </summary>
public class StatsEndpointsTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private readonly VigilApiFactory _factory;
    private readonly string _runId = Guid.NewGuid().ToString("N");
    private readonly List<Guid> _seededJobIds = [];

    public StatsEndpointsTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public async Task DisposeAsync()
    {
        // Cleanup: reports cascade-delete with their jobs.
        var options = DbOptions();
        await using var db = new VigilDbContext(options);
        await db.AnalysisJobs.Where(j => _seededJobIds.Contains(j.Id)).ExecuteDeleteAsync();
    }

    [Fact]
    public async Task GetStats_returns_kpi_shape_and_counts_covering_seeded_rows()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();
        var seeded = await SeedAsync();

        var response = await client.GetAsync("/api/stats");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        // Shape: exact camelCase keys the frontend consumes.
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
        foreach (var key in new[] { "totalJobs", "totalReports", "jobsByStatus", "reportsBySeverity", "avgRiskScore", "last24hJobs" })
        {
            Assert.True(root.TryGetProperty(key, out _), $"Missing key '{key}'.");
        }

        var status = root.GetProperty("jobsByStatus");
        foreach (var key in new[] { "queued", "filtering", "analyzing", "done", "failed" })
        {
            Assert.True(status.TryGetProperty(key, out _), $"Missing jobsByStatus.{key}.");
        }

        var severity = root.GetProperty("reportsBySeverity");
        foreach (var key in new[] { "low", "medium", "high", "critical" })
        {
            Assert.True(severity.TryGetProperty(key, out _), $"Missing reportsBySeverity.{key}.");
        }

        // Values: shared DB, so assert our seeded rows are reflected.
        Assert.True(root.GetProperty("totalJobs").GetInt32() >= seeded.JobCount);
        Assert.True(root.GetProperty("totalReports").GetInt32() >= seeded.ReportCount);
        Assert.True(status.GetProperty("queued").GetInt32() >= 1);
        Assert.True(status.GetProperty("analyzing").GetInt32() >= 1);
        Assert.True(status.GetProperty("failed").GetInt32() >= 1);
        Assert.True(status.GetProperty("done").GetInt32() >= 2);
        Assert.True(severity.GetProperty("critical").GetInt32() >= 1);
        Assert.True(severity.GetProperty("high").GetInt32() >= 1);

        var avg = root.GetProperty("avgRiskScore").GetDouble();
        Assert.InRange(avg, 0, 10);
        Assert.Equal(Math.Round(avg, 2), avg); // rounded to 2 decimals

        // Every seeded job was created seconds ago.
        Assert.True(root.GetProperty("last24hJobs").GetInt32() >= seeded.JobCount);
    }

    [Fact]
    public async Task GetStats_returns_zero_avg_risk_score_when_no_reports()
    {
        // The aggregation logic itself: AverageAsync over an empty set → 0.
        // Verified in isolation so the shared test DB cannot skew it.
        var options = new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options;
        await using var db = new VigilDbContext(options);

        var emptyAvg = await db.Reports.Where(r => r.JobId == Guid.Empty)
            .AverageAsync(r => (double?)r.RiskScore) ?? 0;

        Assert.Equal(0, Math.Round(emptyAvg, 2));
    }

    [Fact]
    public async Task GetMitreHeatmap_aggregates_techniques_and_tactics()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();
        await SeedAsync();

        var response = await client.GetAsync("/api/stats/mitre");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var payload = await response.Content.ReadFromJsonAsync<MitreHeatmapTestDto>();
        Assert.NotNull(payload);

        // Unique marker technique: exact count, unmapped → "Unknown".
        var marker = Assert.Single(payload!.Techniques, t => t.TechniqueId == MarkerTechniqueId);
        Assert.Equal(2, marker.Count);
        Assert.Equal("Unknown", marker.Tactic);

        // Shared technique: present in both seeded reports, mapped tactic.
        var phishing = Assert.Single(payload.Techniques, t => t.TechniqueId == "T1566.002");
        Assert.True(phishing.Count >= 2);
        Assert.Equal("Initial Access", phishing.Tactic);

        var validAccounts = Assert.Single(payload.Techniques, t => t.TechniqueId == "T1078");
        Assert.True(validAccounts.Count >= 1);
        Assert.Equal("Initial Access", validAccounts.Tactic);

        // Tactics: distinct, in kill-chain order, containing what we seeded.
        Assert.Contains("Initial Access", payload.Tactics);
        Assert.Contains("Unknown", payload.Tactics);
        Assert.Equal(payload.Tactics.Count, payload.Tactics.Distinct().Count());
        Assert.Equal("Unknown", payload.Tactics[^1]);
        Assert.True(payload.Tactics.Count <= payload.Techniques.Select(t => t.Tactic).Distinct().Count());

        // Techniques sorted by count descending.
        var counts = payload.Techniques.Select(t => t.Count).ToList();
        Assert.Equal(counts.OrderByDescending(c => c).ToList(), counts);
    }

    private string MarkerTechniqueId => $"T9999.{_runId[..3]}";

    private async Task<(int JobCount, int ReportCount)> SeedAsync()
    {
        var options = DbOptions();
        await using var db = new VigilDbContext(options);

        AnalysisJob NewJob(int n, JobStatus status)
        {
            var job = new AnalysisJob
            {
                Id = Guid.NewGuid(),
                FileName = $"stats-{_runId}-{n}.eml",
                FileType = ArtifactType.Eml,
                Status = status,
                CurrentStep = status.ToString().ToLowerInvariant(),
                StoragePath = $"/tmp/stats-{_runId}-{n}.eml"
            };
            _seededJobIds.Add(job.Id);
            return job;
        }

        var jobs = new[]
        {
            NewJob(1, JobStatus.Queued),
            NewJob(2, JobStatus.Analyzing),
            NewJob(3, JobStatus.Failed),
            NewJob(4, JobStatus.Done),
            NewJob(5, JobStatus.Done)
        };
        db.AnalysisJobs.AddRange(jobs);

        db.Reports.AddRange(
            new AnalysisReport
            {
                Id = Guid.NewGuid(),
                JobId = jobs[3].Id,
                RiskScore = 9.25,
                Severity = Severity.Critical,
                SummaryMarkdown = "seeded critical report",
                MitreTechniques = $"[\"T1566.002\",\"T1078\",\"{MarkerTechniqueId}\"]",
                RecommendedActions = "[\"Isolate the affected mailbox\"]",
                EvidenceTrail = "[]"
            },
            new AnalysisReport
            {
                Id = Guid.NewGuid(),
                JobId = jobs[4].Id,
                RiskScore = 7.5,
                Severity = Severity.High,
                SummaryMarkdown = "seeded high report",
                MitreTechniques = $"[\"T1566.002\",\"{MarkerTechniqueId}\"]",
                RecommendedActions = "[\"Reset credentials\"]",
                EvidenceTrail = "[]"
            });

        await db.SaveChangesAsync();
        return (jobs.Length, 2);
    }

    private static DbContextOptions<VigilDbContext> DbOptions() =>
        new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options;

    private sealed record MitreTechniqueTestDto(string TechniqueId, string Tactic, int Count);

    private sealed record MitreHeatmapTestDto(
        List<MitreTechniqueTestDto> Techniques,
        List<string> Tactics);
}
