using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Core.Ml;
using Vigil.Infrastructure.Ml;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.Tier2;

namespace Vigil.IntegrationTests;

/// <summary>
/// Step 9 acceptance: with ≥3 completed reports indexed in pgvector (clearly
/// distinct topics: phishing email / brute-force login / malware C2), a query
/// semantically close to one topic retrieves that incident in the top-3 — in
/// practice top-1. Embeddings come from the real ONNX MiniLM model, so the
/// tests skip (not fail) when models/minilm.onnx has not been exported.
///
/// Seeded rows are marked with a "rag-seed-" file-name prefix and re-seeded
/// per test so leftover rows from earlier runs cannot skew the ranking; other
/// test classes never write incident_embeddings.
/// </summary>
public class RagRetrievalTests : IAsyncLifetime
{
    private const string SeedMarker = "rag-seed-";

    // Topic summaries match the themes of tests/fixtures/embedding_baseline.json.
    private static readonly (string Topic, string Summary, string[] Rules, string[] Iocs)[] Seeds =
    [
        ("phishing",
            "Credential-harvesting phishing email impersonating a bank, urging the victim to verify their account through a lookalike login portal.",
            ["spf_fail", "lookalike_domain"],
            ["globalsecure-bank-verify-login.com", "http://globalsecure-bank-verify-login.com/session/review"]),
        ("bruteforce",
            "Brute-force login attack: hundreds of failed SSH password attempts against the admin account from a single external IP address.",
            ["recon_burst:admin:42"],
            ["203.0.113.77"]),
        ("c2",
            "Malware infection beaconing to a command-and-control server with periodic HTTP callbacks to a known botnet domain.",
            ["eicar_signature", "suspicious_user_agent"],
            ["botnet-c2.example.net"])
    ];

    private static readonly string RepoRoot = FindRepoRoot();

    private OnnxEmbeddingService? _embedding;
    private readonly Dictionary<string, Guid> _jobIds = new();

    public async Task InitializeAsync()
    {
        if (!File.Exists(ModelPath))
        {
            return; // tests will skip; nothing to seed
        }

        _embedding = new OnnxEmbeddingService(
            ModelPath, VocabPath, enabled: true, NullLogger<OnnxEmbeddingService>.Instance);

        await using var db = CreateDbContext();
        var stale = await db.AnalysisJobs.Where(j => j.FileName.StartsWith(SeedMarker)).ToListAsync();
        db.AnalysisJobs.RemoveRange(stale); // cascades to tier1/report/embedding rows
        await db.SaveChangesAsync();

        var similarity = new IncidentSimilarityService(db, _embedding, NullLogger<IncidentSimilarityService>.Instance);
        foreach (var (topic, summary, rules, iocs) in Seeds)
        {
            var job = new AnalysisJob
            {
                Id = Guid.NewGuid(),
                FileName = SeedMarker + topic + ".eml",
                FileType = ArtifactType.Eml,
                Status = JobStatus.Done,
                StoragePath = "/nonexistent/" + topic + ".eml",
                Tier1Result = new Tier1Result
                {
                    Id = Guid.NewGuid(),
                    ScrubbedPayload = summary,
                    RuleCheckResults = $$"""{"matchedRules":{{System.Text.Json.JsonSerializer.Serialize(rules)}},"extracted":{},"riskScore":60}""",
                    Verdict = Tier1Verdict.Suspicious
                }
            };
            job.Tier1Result.JobId = job.Id;

            var report = new AnalysisReport
            {
                Id = Guid.NewGuid(),
                JobId = job.Id,
                RiskScore = 8.4,
                Severity = Severity.Critical,
                SummaryMarkdown = summary,
                MitreTechniques = "[\"T1566.001\"]",
                RecommendedActions = "[\"Block the sender\"]",
                EvidenceTrail = "[{\"claim\":\"seeded\",\"source\":\"rag-test\"}]"
            };

            db.AnalysisJobs.Add(job);
            db.Reports.Add(report);
            await similarity.IndexReportAsync(report, iocs);
            _jobIds[topic] = job.Id;
        }

        await db.SaveChangesAsync();
    }

    public async Task DisposeAsync()
    {
        await using var db = CreateDbContext();
        var seeded = await db.AnalysisJobs.Where(j => j.FileName.StartsWith(SeedMarker)).ToListAsync();
        db.AnalysisJobs.RemoveRange(seeded);
        await db.SaveChangesAsync();
        _embedding?.Dispose();
    }

    [SkippableFact]
    public async Task Phishing_query_retrieves_the_phishing_incident_first()
    {
        Skip.IfNot(File.Exists(ModelPath),
            "models/minilm.onnx missing — run tools/export_embedding_onnx.py in the Python venv first.");

        await using var db = CreateDbContext();
        var similarity = new IncidentSimilarityService(db, _embedding!, NullLogger<IncidentSimilarityService>.Instance);

        var results = await similarity.FindSimilarAsync(
            "Suspicious email asking employees to enter their banking credentials on a fake verification page.",
            excludeJobId: null);

        Assert.Equal(Seeds.Length, results.Count); // top-3 over 3 seeded incidents
        var phishing = results[0];
        Assert.Equal(Severity.Critical.ToString(), phishing.Severity);
        Assert.Contains("Credential-harvesting", phishing.SummaryExcerpt);
        Assert.Contains("spf_fail", phishing.MatchedRules);
        Assert.True(phishing.Similarity is > 0.5 and <= 1.0);

        // The semantically closest incident must rank well above the other topics.
        Assert.True(results[0].Similarity > results[1].Similarity + 0.1,
            $"top-1 similarity {results[0].Similarity:F3} should clearly beat {results[1].Similarity:F3}");
    }

    [SkippableFact]
    public async Task Brute_force_query_retrieves_the_brute_force_incident_in_top3()
    {
        Skip.IfNot(File.Exists(ModelPath),
            "models/minilm.onnx missing — run tools/export_embedding_onnx.py in the Python venv first.");

        await using var db = CreateDbContext();
        var similarity = new IncidentSimilarityService(db, _embedding!, NullLogger<IncidentSimilarityService>.Instance);

        var results = await similarity.FindSimilarAsync(
            "Thousands of failed password attempts against the VPN gateway from one IP.",
            excludeJobId: null);

        Assert.Contains(results, r => r.SummaryExcerpt.Contains("Brute-force"));
        Assert.StartsWith("Brute-force", results[0].SummaryExcerpt);
    }

    [SkippableFact]
    public async Task Current_job_is_excluded_from_retrieval()
    {
        Skip.IfNot(File.Exists(ModelPath),
            "models/minilm.onnx missing — run tools/export_embedding_onnx.py in the Python venv first.");

        await using var db = CreateDbContext();
        var similarity = new IncidentSimilarityService(db, _embedding!, NullLogger<IncidentSimilarityService>.Instance);

        var results = await similarity.FindSimilarAsync(
            "Credential-harvesting phishing email impersonating a bank login portal.",
            excludeJobId: _jobIds["phishing"]);

        Assert.Equal(Seeds.Length - 1, results.Count);
        Assert.DoesNotContain(results, r => r.SummaryExcerpt.Contains("Credential-harvesting"));
    }

    [Fact]
    public async Task Disabled_embedding_service_skips_retrieval_silently()
    {
        var disabled = new DisabledEmbeddingService();
        await using var db = CreateDbContext();
        var similarity = new IncidentSimilarityService(db, disabled, NullLogger<IncidentSimilarityService>.Instance);

        var results = await similarity.FindSimilarAsync("anything", excludeJobId: null);

        Assert.Empty(results);
        Assert.False(disabled.Called);
    }

    private static string ModelPath => Path.Combine(RepoRoot, "models", "minilm.onnx");

    private static string VocabPath => Path.Combine(RepoRoot, "models", "vocab.txt");

    private static VigilDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options);

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Vigil.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName
            ?? throw new InvalidOperationException("Could not locate the repository root (Vigil.sln).");
    }

    /// <summary>Proves the disabled path never reaches the model.</summary>
    private sealed class DisabledEmbeddingService : IEmbeddingService
    {
        public bool Enabled => false;
        public bool Called { get; private set; }

        public Task<float[]?> EmbedAsync(string text, CancellationToken cancellationToken = default)
        {
            Called = true;
            return Task.FromResult<float[]?>(null);
        }
    }
}
