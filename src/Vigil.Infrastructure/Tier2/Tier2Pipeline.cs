using System.Text.Json;
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
    /// <summary>Tier 2 completed; the report is persisted and the job is Done with CurrentStep "done".</summary>
    Completed,

    /// <summary>The pipeline failed; the job is marked Failed with an ErrorMessage.</summary>
    Failed,

    /// <summary>No job row for the id.</summary>
    JobNotFound,

    /// <summary>The job is not waiting for Tier 2 (already processed, done, or failed earlier).</summary>
    NotPending
}

/// <summary>
/// Result of a Tier 2 run; carries the email analysis and the synthesized
/// report content (the persisted row can be re-read from <c>reports</c>).
/// </summary>
public sealed record Tier2Run(
    Tier2Outcome Outcome,
    EmailAnalysisResult? EmailAnalysis = null,
    SynthesisResult? Synthesis = null);

/// <summary>
/// Drives one Suspicious job through the deterministic Tier 2 state machine
/// (<see cref="Tier2StateMachine"/>): seeds rule-based IOCs from the Tier 1
/// report, runs the LLM email analyst for .eml artifacts, enriches all IOCs
/// with threat intel, then synthesizes and persists the final
/// <see cref="AnalysisReport"/> (LLM, or the deterministic fallback when no
/// LLM key is configured) and marks the job Done. The LLM never decides the
/// path — it only analyzes within a stage. Processing errors mark the job
/// Failed; only persistence failures propagate (same policy as
/// <c>Tier1Pipeline</c>).
/// </summary>
public sealed class Tier2Pipeline(
    VigilDbContext db,
    LlmKernelProvider llm,
    EmailAnalystStage emailAnalyst,
    ThreatIntelStage threatIntelStage,
    SynthesisStage synthesisStage,
    ILogger<Tier2Pipeline> logger)
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public async Task<Tier2Run> ProcessAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        var job = await db.AnalysisJobs
            .Include(j => j.Tier1Result)
            .Include(j => j.Report)
            .FirstOrDefaultAsync(j => j.Id == jobId, cancellationToken);

        if (job is null)
        {
            logger.LogWarning("Job {JobId} not found; skipping Tier 2", jobId);
            return new Tier2Run(Tier2Outcome.JobNotFound);
        }

        if (job.Status != JobStatus.Analyzing || job.Report is not null)
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
            // A job left at synthesis_pending by a crash re-enters at synthesis;
            // the in-memory email analysis is then unavailable and the report is
            // built from the persisted evidence alone.
            var resumeAtSynthesis = job.CurrentStep
                == Tier2StateMachine.StepName(Tier2State.SynthesisPending);

            EmailAnalysisResult? analysis = null;
            if (!resumeAtSynthesis)
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
            }

            job.CurrentStep = Tier2StateMachine.StepName(Tier2State.Synthesis);
            await db.SaveChangesAsync(cancellationToken);

            var synthesis = await synthesisStage.SynthesizeAsync(job, analysis, cancellationToken);
            PersistReport(job, synthesis);

            job.Status = JobStatus.Done;
            job.CurrentStep = "done";
            job.FinishedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(cancellationToken);

            logger.LogInformation("Job {JobId} done: risk {RiskScore:F1}, severity {Severity}",
                jobId, synthesis.RiskScore, synthesis.Severity);
            return new Tier2Run(Tier2Outcome.Completed, analysis, synthesis);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Job {JobId} failed during Tier 2", jobId);
            return await FailAsync(job, ex.Message, cancellationToken);
        }
    }

    private void PersistReport(AnalysisJob job, SynthesisResult synthesis)
    {
        var report = new AnalysisReport
        {
            Id = Guid.NewGuid(),
            JobId = job.Id,
            RiskScore = synthesis.RiskScore,
            Severity = synthesis.Severity,
            SummaryMarkdown = synthesis.SummaryMarkdown,
            MitreTechniques = JsonSerializer.Serialize(synthesis.MitreTechniques, ReportJsonOptions),
            RecommendedActions = JsonSerializer.Serialize(synthesis.RecommendedActions, ReportJsonOptions),
            EvidenceTrail = JsonSerializer.Serialize(synthesis.EvidenceTrail, ReportJsonOptions),
            CreatedAt = DateTimeOffset.UtcNow
        };
        // Explicit Add: assigning through job.Report with a pre-set Guid key would
        // make EF track the report as Unchanged and issue an UPDATE (0 rows).
        db.Reports.Add(report);
        job.Report = report;
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
