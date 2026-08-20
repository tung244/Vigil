using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Vigil.Core.Domain;
using Vigil.Core.Ml;
using Vigil.Core.Tier2;
using Vigil.Infrastructure.Llm;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.ThreatIntel;
using Vigil.Infrastructure.Tier1;
using Vigil.Infrastructure.Tier2;
using Vigil.IntegrationTests.Llm;

namespace Vigil.IntegrationTests;

/// <summary>
/// Step 8 end-to-end: Tier 1 Suspicious → Tier 2 (fake LLM) → Synthesis →
/// persisted reports row, job Done, and GET /api/jobs/{id}/report serving the
/// parsed report DTO. Threat intel runs the real cache-first service with
/// empty API keys (heuristic fallback, no network).
///
/// These tests process mail1.eml while Tier2PipelineTests processes email.eml:
/// the threat intel cache is shared across jobs in the same database, so two
/// test classes enriching the same IOC values in parallel would race on cache
/// hits (a cached row belongs to the other job's Ioc).
/// </summary>
public class SynthesisPipelineTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private const string CannedAnalysis = """
        {
          "status": "phishing",
          "confidence": 0.9,
          "iocs": [{"type": "domain", "value": "globalsecure-bank-verify-login.com"}],
          "phishing_indicators": ["urgency language"],
          "summary": "Credential-harvesting lure impersonating a banking review portal."
        }
        """;

    private const string CannedSynthesis = """
        {
          "risk_score": 8.2,
          "severity": "critical",
          "summary_markdown": "# Incident Report\nCredential-harvesting phishing email with a lookalike review portal.",
          "mitre_techniques": ["T1566.002"],
          "recommended_actions": ["Block the sender domain", "Reset affected credentials"],
          "evidence_trail": [
            {"claim": "Sender fails SPF", "source": "rule:spf_fail"},
            {"claim": "Phishing lure URL present", "source": "ioc:url=http://globalsecure-bank-verify-login.com/session/review"}
          ]
        }
        """;

    /// <summary>Valid JSON, but risk 8.2 demands "critical" — the validator must reject "low".</summary>
    private const string SeverityMismatchSynthesis = """
        {
          "risk_score": 8.2,
          "severity": "low",
          "summary_markdown": "# Incident Report\nMismatch.",
          "mitre_techniques": ["T1566.002"],
          "recommended_actions": ["Block the sender domain"],
          "evidence_trail": [{"claim": "SPF failed", "source": "rule:spf_fail"}]
        }
        """;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    private readonly VigilApiFactory _factory;
    private readonly List<Guid> _createdJobIds = [];

    public SynthesisPipelineTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public async Task DisposeAsync()
    {
        await using var db = CreateDbContext();
        db.AnalysisJobs.RemoveRange(db.AnalysisJobs.Where(j => _createdJobIds.Contains(j.Id)));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Suspicious_eml_flows_end_to_end_into_a_persisted_report()
    {
        var jobId = await UploadFixtureAsync("mail1.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService(CannedAnalysis, CannedSynthesis);

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, run.Outcome);
        Assert.Equal(2, fake.CallCount);

        var job = await db.AnalysisJobs.Include(j => j.Report).SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Done, job.Status);
        Assert.Equal("done", job.CurrentStep);
        Assert.NotNull(job.FinishedAt);

        var report = job.Report!;
        Assert.NotNull(report);
        Assert.Equal(8.2, report.RiskScore);
        Assert.Equal(Severity.Critical, report.Severity);
        Assert.Contains("Credential-harvesting", report.SummaryMarkdown);
        Assert.Contains("T1566.002", report.MitreTechniques);
        Assert.Contains("rule:spf_fail", report.EvidenceTrail);
        Assert.Contains("Block the sender domain", report.RecommendedActions);

        // The API serves the same report with jsonb columns parsed into arrays.
        var client = await _factory.CreateAuthenticatedClientAsync();
        var response = await client.GetAsync($"/api/jobs/{jobId}/report");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var dto = await response.Content.ReadFromJsonAsync<ReportTestDto>(JsonOptions);
        Assert.NotNull(dto);
        Assert.Equal(jobId, dto!.JobId);
        Assert.Equal(8.2, dto.RiskScore);
        Assert.Equal("critical", dto.Severity);
        Assert.Equal(["T1566.002"], dto.MitreTechniques);
        Assert.Equal(2, dto.RecommendedActions.Count);
        Assert.Equal(2, dto.EvidenceTrail.Count);
        Assert.Contains(dto.EvidenceTrail, e => e.Claim == "Sender fails SPF" && e.Source == "rule:spf_fail");

        // The job summary now reports hasReport=true.
        var summaryResponse = await client.GetAsync($"/api/jobs/{jobId}");
        summaryResponse.EnsureSuccessStatusCode();
        using var summary = JsonDocument.Parse(await summaryResponse.Content.ReadAsStringAsync());
        Assert.True(summary.RootElement.GetProperty("hasReport").GetBoolean());
    }

    [Fact]
    public async Task Synthesis_validator_retries_once_on_severity_mismatch()
    {
        var jobId = await UploadFixtureAsync("mail1.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService(CannedAnalysis, SeverityMismatchSynthesis, CannedSynthesis);

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, run.Outcome);
        Assert.Equal(3, fake.CallCount);
        // The retry spelled out the validation violation.
        Assert.Contains("does not match risk_score", fake.ReceivedLastUserMessages[2]);
        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Done, job.Status);
    }

    [Fact]
    public async Task Persistently_invalid_synthesis_fails_the_job()
    {
        var jobId = await UploadFixtureAsync("mail1.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService(CannedAnalysis, SeverityMismatchSynthesis, SeverityMismatchSynthesis);

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Failed, run.Outcome);
        Assert.Equal(3, fake.CallCount);
        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Contains("report contract", job.ErrorMessage);
        Assert.Null(await db.Reports.SingleOrDefaultAsync(r => r.JobId == jobId));
    }

    [Fact]
    public async Task Report_endpoint_returns_404_for_unknown_job()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        var response = await client.GetAsync($"/api/jobs/{Guid.NewGuid()}/report");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Report_endpoint_returns_409_while_job_has_no_report()
    {
        var jobId = await UploadFixtureAsync("email.eml"); // uploaded, never processed
        var client = await _factory.CreateAuthenticatedClientAsync();

        var response = await client.GetAsync($"/api/jobs/{jobId}/report");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("no report", body, StringComparison.OrdinalIgnoreCase);
    }

    // ── helpers ──────────────────────────────────────────────────────────

    private static LlmKernelProvider WithFakeChat(FakeChatCompletionService fake)
    {
        var builder = Kernel.CreateBuilder();
        builder.Services.AddSingleton<IChatCompletionService>(fake);
        return new LlmKernelProvider(builder.Build());
    }

    private Tier2Pipeline CreateTier2Pipeline(LlmKernelProvider provider, out VigilDbContext db)
    {
        db = CreateDbContext();
        var options = new ThreatIntelOptions
        {
            VirusTotalApiKey = "",
            AbuseIpDbApiKey = "",
            CacheHours = 24
        };
        var intel = new ThreatIntelService(
            db,
            new VirusTotalClient(new HttpClient(new ThrowingHandler()), options, NullLogger<VirusTotalClient>.Instance),
            new AbuseIpDbClient(new HttpClient(new ThrowingHandler()), options, NullLogger<AbuseIpDbClient>.Instance),
            options,
            NullLogger<ThreatIntelService>.Instance);
        return new Tier2Pipeline(
            db,
            provider,
            new EmailAnalystStage(provider, NullLogger<EmailAnalystStage>.Instance),
            new ThreatIntelStage(db, intel, NullLogger<ThreatIntelStage>.Instance),
            new SynthesisStage(db, provider, NullLogger<SynthesisStage>.Instance),
            NullLogger<Tier2Pipeline>.Instance);
    }

    private async Task<Guid> UploadFixtureAsync(string fixtureName)
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        var fixturePath = Path.Combine(AppContext.BaseDirectory, "fixtures", fixtureName);
        await using var fileStream = File.OpenRead(fixturePath);
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(fileStream);
        content.Add(fileContent, "file", fixtureName);

        var response = await client.PostAsync("/api/jobs", content);
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        var accepted = await response.Content.ReadFromJsonAsync<JobAcceptedTestDto>();
        Assert.NotNull(accepted);
        _createdJobIds.Add(accepted!.JobId);
        return accepted.JobId;
    }

    private async Task RunTier1Async(Guid jobId)
    {
        await using var db = CreateDbContext();
        var pipeline = new Tier1Pipeline(
            db, new FakePhishingClassifier(), NullLogger<Tier1Pipeline>.Instance);
        var outcome = await pipeline.ProcessAsync(jobId);
        Assert.Equal(Tier1Outcome.Completed, outcome);
    }

    private static VigilDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options);

    private sealed record JobAcceptedTestDto(Guid JobId, string Status);

    private sealed record EvidenceItemTestDto(string Claim, string Source);

    private sealed record ReportTestDto(
        Guid JobId,
        double RiskScore,
        string Severity,
        string SummaryMarkdown,
        IReadOnlyList<string> MitreTechniques,
        IReadOnlyList<string> RecommendedActions,
        IReadOnlyList<EvidenceItemTestDto> EvidenceTrail,
        DateTimeOffset CreatedAt);

    /// <summary>Low, non-escalating score; the fixtures' rules drive the verdict.</summary>
    private sealed class FakePhishingClassifier : IPhishingClassifier
    {
        public bool Enabled => true;
        public double Threshold => 0.7;
        public double Classify(string? subject, string body) => 0.05;
    }

    /// <summary>Proves no HTTP call is attempted (empty keys → heuristic fallback first).</summary>
    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No HTTP call expected in synthesis tests.");
    }
}
