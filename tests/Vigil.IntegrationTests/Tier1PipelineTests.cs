using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Core.Ml;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.Tier1;
using Xunit;

namespace Vigil.IntegrationTests;

/// <summary>
/// End-to-end Tier 1: upload an artifact through the API, then run the same
/// pipeline the Worker hosts (invoked directly for determinism) and assert the
/// job status transition plus the persisted tier1_results row.
/// Requires docker-compose services running (Step 1).
/// </summary>
public class Tier1PipelineTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private readonly VigilApiFactory _factory;
    private readonly List<Guid> _createdJobIds = [];

    public Tier1PipelineTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public async Task DisposeAsync()
    {
        await using var db = CreateDbContext();
        db.AnalysisJobs.RemoveRange(db.AnalysisJobs.Where(j => _createdJobIds.Contains(j.Id)));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Uploaded_eml_reaches_analyzing_with_suspicious_tier1_result()
    {
        var jobId = await UploadFixtureAsync("email.eml");

        var outcome = await RunPipelineAsync(jobId);

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        Assert.Equal(JobStatus.Analyzing, job.Status);
        Assert.Equal("tier2.pending", job.CurrentStep);
        Assert.NotNull(job.StartedAt);
        Assert.Null(job.FinishedAt); // Tier 2 (Step 7) picks it up from here

        var result = job.Tier1Result;
        Assert.NotNull(result);
        Assert.Equal(Tier1Verdict.Suspicious, result!.Verdict);
        Assert.Equal(FakePhishingClassifier.LowScore, result.MlScore);
        Assert.Contains("urgent_action_required", result.RuleCheckResults);
        Assert.Contains("ml_phishing", result.RuleCheckResults);
        // PII scrubbing: sender address must not survive into the stored payload.
        Assert.DoesNotContain("notifications@secure-review-mail.example", result.ScrubbedPayload);
        Assert.Contains("[REDACTED_EMAIL]", result.ScrubbedPayload);
    }

    [Fact]
    public async Task Uploaded_suspicious_csv_reaches_analyzing()
    {
        var jobId = await UploadFixtureAsync("authlog_suspicious.csv");

        var outcome = await RunPipelineAsync(jobId);

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        Assert.Equal(JobStatus.Analyzing, job.Status);
        Assert.NotNull(job.Tier1Result);
        Assert.Equal(Tier1Verdict.Suspicious, job.Tier1Result!.Verdict);
        Assert.Contains("high_risk_api:AssumeRole", job.Tier1Result.RuleCheckResults);
        Assert.Contains("sensitive_event_unseen_ip", job.Tier1Result.RuleCheckResults);
    }

    [Fact]
    public async Task Uploaded_benign_csv_reaches_done()
    {
        var jobId = await UploadFixtureAsync("authlog_benign.csv");

        var outcome = await RunPipelineAsync(jobId);

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        Assert.Equal(JobStatus.Done, job.Status);
        Assert.Equal("tier1.done", job.CurrentStep);
        Assert.NotNull(job.FinishedAt);
        Assert.NotNull(job.Tier1Result);
        Assert.Equal(Tier1Verdict.Benign, job.Tier1Result!.Verdict);
    }

    [Fact]
    public async Task High_ml_score_escalates_rule_benign_email_to_analyzing()
    {
        var jobId = await UploadFixtureAsync("benign.eml");

        var outcome = await RunPipelineAsync(
            jobId, new FakePhishingClassifier(FakePhishingClassifier.HighScore));

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        // No rule fires on the benign fixture; the ML score alone escalates.
        Assert.Equal(JobStatus.Analyzing, job.Status);
        Assert.NotNull(job.Tier1Result);
        Assert.Equal(Tier1Verdict.Suspicious, job.Tier1Result!.Verdict);
        Assert.Equal(FakePhishingClassifier.HighScore, job.Tier1Result.MlScore);
        Assert.Contains("ml_phishing", job.Tier1Result.RuleCheckResults);
    }

    [Fact]
    public async Task Low_ml_score_keeps_rule_benign_email_done()
    {
        var jobId = await UploadFixtureAsync("benign.eml");

        var outcome = await RunPipelineAsync(jobId);

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        Assert.Equal(JobStatus.Done, job.Status);
        Assert.NotNull(job.Tier1Result);
        Assert.Equal(Tier1Verdict.Benign, job.Tier1Result!.Verdict);
        Assert.Equal(FakePhishingClassifier.LowScore, job.Tier1Result.MlScore);
    }

    [Fact]
    public async Task Disabled_classifier_leaves_ml_score_null()
    {
        var jobId = await UploadFixtureAsync("benign.eml");

        var outcome = await RunPipelineAsync(jobId, new FakePhishingClassifier(0.0, enabled: false));

        Assert.Equal(Tier1Outcome.Completed, outcome);

        await using var db = CreateDbContext();
        var job = await db.AnalysisJobs.Include(j => j.Tier1Result)
            .SingleAsync(j => j.Id == jobId);

        Assert.Equal(JobStatus.Done, job.Status);
        Assert.NotNull(job.Tier1Result);
        Assert.Null(job.Tier1Result!.MlScore);
        // jsonb normalizes whitespace, so assert on the bare tokens.
        Assert.Contains("ml_phishing", job.Tier1Result.RuleCheckResults);
        Assert.Contains("skipped", job.Tier1Result.RuleCheckResults);
    }

    [Fact]
    public async Task Missing_storage_file_marks_job_failed_without_throwing()
    {
        var jobId = await UploadFixtureAsync("email.eml");

        await using (var db = CreateDbContext())
        {
            var job = await db.AnalysisJobs.SingleAsync(j => j.Id == jobId);
            File.Delete(job.StoragePath);
        }

        var outcome = await RunPipelineAsync(jobId);

        Assert.Equal(Tier1Outcome.Failed, outcome);

        await using var db2 = CreateDbContext();
        var failed = await db2.AnalysisJobs.SingleAsync(j => j.Id == jobId);
        Assert.Equal(JobStatus.Failed, failed.Status);
        Assert.NotNull(failed.ErrorMessage);
        Assert.NotNull(failed.FinishedAt);
    }

    [Fact]
    public async Task Unknown_job_id_is_reported_not_thrown()
    {
        var outcome = await RunPipelineAsync(Guid.NewGuid());

        Assert.Equal(Tier1Outcome.JobNotFound, outcome);
    }

    private async Task<Guid> UploadFixtureAsync(string fixtureName)
    {
        var client = _factory.CreateClient();

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

    private async Task<Tier1Outcome> RunPipelineAsync(Guid jobId, IPhishingClassifier? classifier = null)
    {
        await using var db = CreateDbContext();
        var pipeline = new Tier1Pipeline(
            db, classifier ?? new FakePhishingClassifier(FakePhishingClassifier.LowScore),
            NullLogger<Tier1Pipeline>.Instance);
        return await pipeline.ProcessAsync(jobId);
    }

    private static VigilDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options);

    private sealed record JobAcceptedTestDto(Guid JobId, string Status);

    /// <summary>Deterministic stand-in for the ONNX classifier in pipeline tests.</summary>
    private sealed class FakePhishingClassifier(double score, bool enabled = true) : IPhishingClassifier
    {
        public const double LowScore = 0.05;
        public const double HighScore = 0.95;

        public bool Enabled { get; } = enabled;
        public double Threshold => 0.7;
        public double Classify(string? subject, string body) => score;
    }
}
