using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;
using Vigil.Core.Pipeline;
using Vigil.Core.Tier2;
using Vigil.Infrastructure.Llm;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.Tier2;

/// <summary>Outcome of one <see cref="Tier2Pipeline"/> run.</summary>
public enum Tier2Outcome
{
    /// <summary>Tier 2 completed; the job sits in Analyzing with CurrentStep "tier2.synthesis_pending".</summary>
    Completed,

    /// <summary>The pipeline failed; the job is marked Failed with an ErrorMessage.</summary>
    Failed,

    /// <summary>No job row for the id.</summary>
    JobNotFound,

    /// <summary>The job is not waiting for Tier 2 (already processed, done, or failed earlier).</summary>
    NotPending
}

/// <summary>Result of a Tier 2 run; carries the email analysis for Step 8 synthesis.</summary>
public sealed record Tier2Run(Tier2Outcome Outcome, EmailAnalysisResult? EmailAnalysis = null);

/// <summary>
/// Drives one Suspicious job through the deterministic Tier 2 state machine
/// (<see cref="Tier2StateMachine"/>): seeds rule-based IOCs from the Tier 1
/// report, runs the LLM email analyst for .eml artifacts, enriches all IOCs
/// with threat intel, and leaves the job in "tier2.synthesis_pending" for the
/// report step (Step 8). The LLM never decides the path — it only analyzes
/// within the email stage. Processing errors mark the job Failed; only
/// persistence failures propagate (same policy as <c>Tier1Pipeline</c>).
/// </summary>
public sealed class Tier2Pipeline(
    VigilDbContext db,
    LlmKernelProvider llm,
    EmailAnalystStage emailAnalyst,
    ThreatIntelStage threatIntelStage,
    ILogger<Tier2Pipeline> logger)
{
    public async Task<Tier2Run> ProcessAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        var job = await db.AnalysisJobs
            .Include(j => j.Tier1Result)
            .FirstOrDefaultAsync(j => j.Id == jobId, cancellationToken);

        if (job is null)
        {
            logger.LogWarning("Job {JobId} not found; skipping Tier 2", jobId);
            return new Tier2Run(Tier2Outcome.JobNotFound);
        }

        if (job.Status != JobStatus.Analyzing
            || job.CurrentStep == Tier2StateMachine.StepName(Tier2State.SynthesisPending))
        {
            logger.LogInformation("Job {JobId} is not pending Tier 2 (status={Status}, step={Step}); skipping",
                jobId, job.Status, job.CurrentStep);
            return new Tier2Run(Tier2Outcome.NotPending);
        }

        if (job.Tier1Result is null)
        {
            return await FailAsync(job, "Tier 1 result missing for a job in Analyzing; cannot run Tier 2.",
                cancellationToken);
        }

        try
        {
            // IOCs the rules already extracted become Ioc rows (ExtractedBy=Rule)
            // before any LLM output is merged in.
            var ruleReport = RuleIocSeeder.TryReadReport(job.Tier1Result.RuleCheckResults);
            if (ruleReport is not null)
            {
                var seeded = await RuleIocSeeder.SeedAsync(db, job.Id, ruleReport, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
                logger.LogInformation("Job {JobId}: seeded {Count} rule-based IOCs", jobId, seeded);
            }

            EmailAnalysisResult? analysis = null;
            var state = Tier2StateMachine.InitialState(job.FileType);
            while (state != Tier2State.SynthesisPending)
            {
                job.CurrentStep = Tier2StateMachine.StepName(state);
                await db.SaveChangesAsync(cancellationToken);

                switch (state)
                {
                    case Tier2State.EmailAnalysis:
                        if (!llm.IsConfigured)
                        {
                            throw new LlmNotConfiguredException(
                                "LLM not configured: set Llm:ApiKey (provider gemini) to enable the email analyst stage.");
                        }
                        analysis = await emailAnalyst.AnalyzeAsync(
                            job.Tier1Result.ScrubbedPayload,
                            ruleReport?.MatchedRules ?? [],
                            cancellationToken);
                        await PersistLlmIocsAsync(job.Id, analysis, cancellationToken);
                        break;

                    case Tier2State.ThreatIntelEnrichment:
                        await threatIntelStage.EnrichAsync(job.Id, cancellationToken);
                        break;
                }

                state = Tier2StateMachine.Next(state);
            }

            job.CurrentStep = Tier2StateMachine.StepName(Tier2State.SynthesisPending);
            await db.SaveChangesAsync(cancellationToken);

            logger.LogInformation("Job {JobId} Tier 2 complete: {State}", jobId, job.CurrentStep);
            return new Tier2Run(Tier2Outcome.Completed, analysis);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {JobId} failed during Tier 2", jobId);
            return await FailAsync(job, ex.Message, cancellationToken);
        }
    }

    /// <summary>
    /// Persists LLM-reported IOCs (ExtractedBy=Llm), skipping values the rule
    /// seeder already stored for this job.
    /// </summary>
    private async Task PersistLlmIocsAsync(
        Guid jobId, EmailAnalysisResult analysis, CancellationToken cancellationToken)
    {
        var existing = await db.Iocs.Where(i => i.JobId == jobId)
            .Select(i => new { i.Type, i.Value })
            .ToListAsync(cancellationToken);
        var existingKeys = existing
            .Select(e => (e.Type, Value: e.Value.ToLowerInvariant()))
            .ToHashSet();

        var added = 0;
        foreach (var ioc in analysis.Iocs)
        {
            if (existingKeys.Add((ioc.Type, ioc.Value.ToLowerInvariant())))
            {
                db.Iocs.Add(new Ioc
                {
                    Id = Guid.NewGuid(),
                    JobId = jobId,
                    Type = ioc.Type,
                    Value = ioc.Value,
                    ExtractedBy = IocExtractor.Llm
                });
                added++;
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        logger.LogInformation("Job {JobId}: persisted {Count} LLM-extracted IOCs ({Duplicates} duplicates skipped)",
            jobId, added, analysis.Iocs.Count - added);
    }

    private async Task<Tier2Run> FailAsync(AnalysisJob job, string message, CancellationToken cancellationToken)
    {
        job.Status = JobStatus.Failed;
        job.CurrentStep = "tier2.failed";
        job.ErrorMessage = message;
        job.FinishedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return new Tier2Run(Tier2Outcome.Failed);
    }
}
