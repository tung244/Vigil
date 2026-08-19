using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;
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
/// scrubbing, artifact-specific rule checks, tier1_results persistence and the
/// final status transition. Tier 2 (Step 7) picks up jobs left in Analyzing.
/// Processing exceptions are caught here and recorded on the job; only
/// infrastructure failures (e.g. the database being unreachable while saving)
/// propagate so the caller can requeue the message.
/// </summary>
public sealed class Tier1Pipeline(VigilDbContext db, ILogger<Tier1Pipeline> logger)
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
            var scrubbedPayload = PiiScrubber.Scrub(rawContent);
            var report = RunRuleChecks(job.FileType, rawContent);

            db.Tier1Results.Add(new Tier1Result
            {
                Id = Guid.NewGuid(),
                JobId = job.Id,
                ScrubbedPayload = scrubbedPayload,
                RuleCheckResults = JsonSerializer.Serialize(report, JsonOptions),
                MlScore = null, // ONNX classifier arrives in Step 5
                Verdict = report.Verdict
            });

            if (report.Verdict == Tier1Verdict.Suspicious)
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
                "Job {JobId} Tier 1 complete: {Verdict} (rules={RuleCount}, score={Score})",
                jobId, report.Verdict, report.MatchedRules.Count, report.RiskScore);

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
