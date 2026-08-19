using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;
using Vigil.Core.Ml;
using Vigil.Core.Security;
using Vigil.Core.Tier1;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.Tier1;

/// <summary>Outcome of one <see cref="Tier1Pipeline"/> run.</summary>
public enum Tier1Outcome
{
    /// <summary>Tier 1 completed; the job advanced to Analyzing or Done.</summary>
    Completed,

    /// <summary>The pipeline failed; the job is marked Failed and the message may be acked.</summary>
    Failed,

    /// <summary>No job row for the id; the message may be acked and forgotten.</summary>
    JobNotFound,

    /// <summary>Tier 1 already ran for this job (redelivered message); nothing to do.</summary>
    AlreadyProcessed
}

/// <summary>
/// Drives one job through Tier 1: status transition Queued → Filtering, PII
/// scrubbing, artifact-specific rule checks, ONNX phishing scoring for .eml
/// artifacts, tier1_results persistence and the final status transition.
/// Tier 2 (Step 7) picks up jobs left in Analyzing. Processing exceptions are
/// caught here and recorded on the job; only infrastructure failures (e.g. the
/// database being unreachable while saving) propagate so the caller can
/// requeue the message.
/// </summary>
public sealed class Tier1Pipeline(
    VigilDbContext db,
    IPhishingClassifier phishingClassifier,
    ILogger<Tier1Pipeline> logger)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() }
    };

    public async Task<Tier1Outcome> ProcessAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        var job = await db.AnalysisJobs
            .Include(j => j.Tier1Result)
            .FirstOrDefaultAsync(j => j.Id == jobId, cancellationToken);

        if (job is null)
        {
            logger.LogWarning("Job {JobId} not found; discarding message", jobId);
            return Tier1Outcome.JobNotFound;
        }

        if (job.Tier1Result is not null)
        {
            logger.LogInformation("Job {JobId} already has a Tier 1 result; skipping", jobId);
            return Tier1Outcome.AlreadyProcessed;
        }

        job.Status = JobStatus.Filtering;
        job.CurrentStep = "tier1.filtering";
        job.StartedAt ??= DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        try
        {
            var rawContent = await File.ReadAllTextAsync(job.StoragePath, cancellationToken);

            // Rules run on the raw artifact (PII can itself be an IOC); the
            // scrubbed text is what later tiers and LLM agents are allowed to see.
            // The ML classifier intentionally scores the scrubbed text: that is
            // the payload the rest of the system reasons about, and it keeps the
            // phishing score reproducible from tier1_results alone.
            var scrubbedPayload = PiiScrubber.Scrub(rawContent);
            var report = RunRuleChecks(job.FileType, rawContent);
            var mlScore = ScoreWithClassifier(job.FileType, scrubbedPayload, report);

            // Verdict policy: any matched rule OR an ML phishing score at/above
            // the configured threshold escalates to Suspicious.
            var verdict = report.Verdict == Tier1Verdict.Suspicious
                          || (mlScore is not null && mlScore >= phishingClassifier.Threshold)
                ? Tier1Verdict.Suspicious
                : Tier1Verdict.Benign;

            db.Tier1Results.Add(new Tier1Result
            {
                Id = Guid.NewGuid(),
                JobId = job.Id,
                ScrubbedPayload = scrubbedPayload,
                RuleCheckResults = JsonSerializer.Serialize(report, JsonOptions),
                MlScore = mlScore,
                Verdict = verdict
            });

            if (verdict == Tier1Verdict.Suspicious)
            {
                job.Status = JobStatus.Analyzing;
                job.CurrentStep = "tier2.pending"; // Tier 2 lands in Step 7
            }
            else
            {
                job.Status = JobStatus.Done;
                job.CurrentStep = "tier1.done";
                job.FinishedAt = DateTimeOffset.UtcNow;
            }

            await db.SaveChangesAsync(cancellationToken);

            logger.LogInformation(
                "Job {JobId} Tier 1 complete: {Verdict} (rules={RuleCount}, score={Score}, mlScore={MlScore})",
                jobId, verdict, report.MatchedRules.Count, report.RiskScore,
                mlScore?.ToString("F3") ?? "n/a");

            return Tier1Outcome.Completed;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {JobId} failed during Tier 1", jobId);

            job.Status = JobStatus.Failed;
            job.CurrentStep = "tier1.failed";
            job.ErrorMessage = ex.Message;
            job.FinishedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            return Tier1Outcome.Failed;
        }
    }

    /// <summary>
    /// Runs the ONNX phishing classifier on the scrubbed subject+body of .eml
    /// artifacts. Returns null when ML is disabled or the artifact is not an
    /// email; the outcome is recorded as an audit check on the rule report.
    /// </summary>
    private double? ScoreWithClassifier(ArtifactType artifactType, string scrubbedPayload, Tier1RuleReport report)
    {
        if (artifactType != ArtifactType.Eml)
        {
            return null; // the phishing classifier only applies to email text
        }

        if (!phishingClassifier.Enabled)
        {
            report.Checks.Add(new RuleCheck(
                "ml_phishing", "skipped", "ML scoring disabled (Ml:Enabled=false)."));
            return null;
        }

        var message = EmlParser.Parse(scrubbedPayload);
        var score = phishingClassifier.Classify(message.Subject, message.Body);
        var flagged = score >= phishingClassifier.Threshold;
        report.Checks.Add(new RuleCheck(
            "ml_phishing", flagged ? "flag" : "pass",
            $"phishing probability {score:F3} (threshold {phishingClassifier.Threshold:F2})."));
        return score;
    }

    private static Tier1RuleReport RunRuleChecks(ArtifactType artifactType, string rawContent) =>
        artifactType switch
        {
            ArtifactType.Eml => EmailRuleChecks.Analyze(rawContent),
            ArtifactType.Csv => CsvLogRuleChecks.Analyze(rawContent),
            // No Tier 1 rules for JSON artifacts yet; escalate rather than drop.
            _ => UnsupportedArtifactReport(artifactType)
        };

    private static Tier1RuleReport UnsupportedArtifactReport(ArtifactType artifactType)
    {
        var report = new Tier1RuleReport
        {
            ArtifactType = artifactType.ToString(),
            Verdict = Tier1Verdict.Suspicious
        };
        report.Checks.Add(new RuleCheck(
            "artifact_type", "info",
            $"No Tier 1 rule checks for {artifactType} artifacts; escalated by default."));
        report.MatchedRules.Add("unsupported_artifact_escalated");
        return report;
    }
}
