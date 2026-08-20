using System.Net;
using System.Net.Http.Json;
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
/// End-to-end Tier 2: upload an artifact, run Tier 1 (fake ONNX classifier),
/// then run the Tier 2 state machine with a fake SK chat completion service
/// in place of Gemini. Threat intel runs the real cache-first service with
/// empty API keys, exercising the heuristic fallback path without any network
/// call (a throwing HTTP handler proves it).
/// </summary>
public class Tier2PipelineTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    /// <summary>LLM answer for the happy path: one rule-overlapping IOC + one new IOC.</summary>
    private const string CannedAnalysis = """
        {
          "status": "phishing",
          "confidence": 0.9,
          "iocs": [
            {"type": "url", "value": "https://training-portal.example/review-session"},
            {"type": "domain", "value": "evil-phish.example"}
          ],
          "phishing_indicators": ["urgency language", "lookalike review portal"],
          "summary": "Credential-harvesting lure impersonating a banking review portal."
        }
        """;

    /// <summary>Valid synthesis report answering the email analysis above.</summary>
    private const string CannedSynthesis = """
        {
          "risk_score": 8.2,
          "severity": "critical",
          "summary_markdown": "# Incident Report\nCredential-harvesting phishing email with a lookalike review portal.",
          "mitre_techniques": ["T1566.002"],
          "recommended_actions": ["Block the sender domain", "Reset affected credentials"],
          "evidence_trail": [
            {"claim": "Sender fails SPF", "source": "rule:spf_fail"},
            {"claim": "Phishing lure URL present", "source": "ioc:url=https://training-portal.example/review-session"}
          ]
        }
        """;

    private readonly VigilApiFactory _factory;
    private readonly List<Guid> _createdJobIds = [];

    public Tier2PipelineTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public async Task DisposeAsync()
    {
        await using var db = CreateDbContext();
        db.AnalysisJobs.RemoveRange(db.AnalysisJobs.Where(j => _createdJobIds.Contains(j.Id)));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Eml_job_completes_tier2_with_llm_iocs_and_intel_results()
    {
        var jobId = await UploadFixtureAsync("email.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService(CannedAnalysis, CannedSynthesis);

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, run.Outcome);
        Assert.NotNull(run.EmailAnalysis);
        Assert.Equal(EmailVerdict.Phishing, run.EmailAnalysis!.Status);
        Assert.NotNull(run.Synthesis);
        Assert.Equal(2, fake.CallCount);

        var job = await db.AnalysisJobs.Include(j => j.Iocs).SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Done, job.Status);
        Assert.Equal("done", job.CurrentStep);
        Assert.Null(job.ErrorMessage);

        // The LLM-only IOC was persisted; the rule-overlapping one was not duplicated.
        Assert.Contains(job.Iocs, i =>
            i.Type == IocType.Domain && i.Value == "evil-phish.example" && i.ExtractedBy == IocExtractor.Llm);
        var ruleUrl = job.Iocs.Where(i => i.Type == IocType.Url && i.Value == "https://training-portal.example/review-session").ToList();
        Assert.Single(ruleUrl);
        Assert.Equal(IocExtractor.Rule, ruleUrl[0].ExtractedBy);
        // Sender address became a rule IOC of type Email.
        Assert.Contains(job.Iocs, i =>
            i.Type == IocType.Email && i.Value == "notifications@secure-review-mail.example");

        // Every non-email IOC got a threat intel row via the heuristic fallback.
        var intel = await db.ThreatIntelResults.Where(r => r.Ioc.JobId == jobId).ToListAsync();
        Assert.NotEmpty(intel);
        Assert.All(intel, r =>
        {
            Assert.False(r.FromLiveApi);
            Assert.Contains("\"fallback\":true", r.RawResponse);
            Assert.Contains("missing_api_key", r.RawResponse);
        });
        var enrichedIocIds = intel.Select(r => r.IocId).Distinct().ToHashSet();
        foreach (var ioc in job.Iocs.Where(i => i.Type != IocType.Email))
        {
            Assert.Contains(ioc.Id, enrichedIocIds);
        }
    }

    [Fact]
    public async Task Csv_job_skips_email_analysis_and_needs_no_llm_key()
    {
        var jobId = await UploadFixtureAsync("authlog_suspicious.csv");
        await RunTier1Async(jobId);
        // No kernel at all: proves the CSV path never touches the LLM.
        var unconfigured = new LlmKernelProvider(new LlmOptions(), NullLogger<LlmKernelProvider>.Instance);
        Assert.False(unconfigured.IsConfigured);

        var run = await CreateTier2Pipeline(unconfigured, out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, run.Outcome);
        Assert.Null(run.EmailAnalysis);
        Assert.NotNull(run.Synthesis);

        var job = await db.AnalysisJobs.Include(j => j.Iocs).SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Done, job.Status);
        Assert.Equal("done", job.CurrentStep);

        // Without an LLM key, synthesis falls back to the deterministic report.
        var report = await db.Reports.SingleAsync(r => r.JobId == jobId);
        Assert.Contains(DeterministicSynthesis.FallbackMarker, report.SummaryMarkdown);

        // Rule IOCs from the CSV report (source IPs) were seeded and enriched.
        Assert.NotEmpty(job.Iocs);
        Assert.All(job.Iocs, i =>
        {
            Assert.Equal(IocType.Ip, i.Type);
            Assert.Equal(IocExtractor.Rule, i.ExtractedBy);
        });
        var intelCount = await db.ThreatIntelResults.CountAsync(r => r.Ioc.JobId == jobId);
        Assert.True(intelCount >= job.Iocs.Count); // VT + AbuseIPDB per IP
    }

    [Fact]
    public async Task Missing_llm_key_fails_email_jobs_with_a_clear_error()
    {
        var jobId = await UploadFixtureAsync("email.eml");
        await RunTier1Async(jobId);
        var unconfigured = new LlmKernelProvider(new LlmOptions(), NullLogger<LlmKernelProvider>.Instance);

        var run = await CreateTier2Pipeline(unconfigured, out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Failed, run.Outcome);
        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Equal("tier2.failed", job.CurrentStep);
        Assert.Contains("LLM not configured", job.ErrorMessage);
        Assert.NotNull(job.FinishedAt);
    }

    [Fact]
    public async Task Malformed_llm_response_is_retried_once_then_accepted()
    {
        var jobId = await UploadFixtureAsync("email.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService("this is not json at all", CannedAnalysis, CannedSynthesis);

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, run.Outcome);
        Assert.Equal(3, fake.CallCount);
        // The retry carried the corrective instruction.
        Assert.Contains(EmailAnalystPrompts.RetryInstruction, fake.ReceivedLastUserMessages[1]);
        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal("done", job.CurrentStep);
    }

    [Fact]
    public async Task Persistently_malformed_llm_response_marks_the_job_failed()
    {
        var jobId = await UploadFixtureAsync("email.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService("garbage", "still garbage");

        var run = await CreateTier2Pipeline(WithFakeChat(fake), out var db).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Failed, run.Outcome);
        Assert.Equal(2, fake.CallCount);
        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Failed, job.Status);
        Assert.Contains("JSON contract", job.ErrorMessage);
    }

    [Fact]
    public async Task Completed_tier2_job_is_not_processed_twice()
    {
        var jobId = await UploadFixtureAsync("email.eml");
        await RunTier1Async(jobId);
        var fake = new FakeChatCompletionService(CannedAnalysis, CannedSynthesis);

        var first = await CreateTier2Pipeline(WithFakeChat(fake), out _).ProcessAsync(jobId);
        var second = await CreateTier2Pipeline(WithFakeChat(fake), out _).ProcessAsync(jobId);

        Assert.Equal(Tier2Outcome.Completed, first.Outcome);
        Assert.Equal(Tier2Outcome.NotPending, second.Outcome);
        Assert.Equal(2, fake.CallCount);
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

        var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Analyzing, job.Status); // precondition for Tier 2
    }

    private static VigilDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options);

    private sealed record JobAcceptedTestDto(Guid JobId, string Status);

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
            throw new InvalidOperationException("No HTTP call expected in Tier 2 tests.");
    }
}
