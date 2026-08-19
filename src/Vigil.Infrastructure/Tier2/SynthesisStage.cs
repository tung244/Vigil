using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Vigil.Core.Domain;
using Vigil.Core.Tier2;
using Vigil.Infrastructure.Llm;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.Tier2;

/// <summary>
/// Final Tier 2 stage: gathers the complete evidence bundle of a job (Tier 1
/// rule report, ML score, IOCs + threat intel results, optional email
/// analysis, correlated CloudTrail events) and produces the incident report.
///
/// With an LLM configured, one prompt asks for the strict JSON contract
/// (<see cref="SynthesisPrompts"/>); the response is parsed and run through
/// the deterministic <see cref="ReportValidator"/> (severity band, MITRE ID
/// format, non-empty evidence trail), with exactly one corrective retry —
/// the port of the old system's synthesis + report_validator repair pass.
///
/// Without an LLM key the stage falls back to <see cref="DeterministicSynthesis"/>:
/// a rule-based report clearly marked "[generated without LLM]". This keeps
/// non-email jobs completable keyless (Tier 2's email stage already fails
/// email jobs without a key, so the fallback mostly serves CSV/JSON) and gives
/// demo resilience instead of a hard failure.
/// </summary>
public sealed class SynthesisStage(
    VigilDbContext db,
    LlmKernelProvider llm,
    ILogger<SynthesisStage> logger)
{
    private const int MaxAttempts = 2;
    private const int MaxCloudtrailEvents = 20;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public async Task<SynthesisResult> SynthesizeAsync(
        AnalysisJob job,
        EmailAnalysisResult? emailAnalysis,
        CancellationToken cancellationToken = default)
    {
        var evidence = await GatherEvidenceAsync(job, emailAnalysis, cancellationToken);

        if (!llm.IsConfigured)
        {
            logger.LogWarning(
                "Job {JobId}: LLM not configured; generating deterministic fallback report", job.Id);
            return DeterministicSynthesis.Build(evidence);
        }

        var chat = llm.Kernel!.Services.GetRequiredService<IChatCompletionService>();

        var history = new ChatHistory(SynthesisPrompts.SystemPrompt);
        history.AddUserMessage(SynthesisPrompts.BuildUserPrompt(JsonSerializer.Serialize(evidence, JsonOptions)));

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            var messages = await chat.GetChatMessageContentsAsync(
                history, cancellationToken: cancellationToken);
            var text = messages.LastOrDefault()?.Content;

            if (!SynthesisResponseParser.TryParse(text, out var result))
            {
                logger.LogWarning("Synthesis response malformed (attempt {Attempt}/{Max})", attempt, MaxAttempts);
                if (attempt < MaxAttempts)
                {
                    history.AddAssistantMessage(text ?? string.Empty);
                    history.AddUserMessage(SynthesisPrompts.FormatRetryInstruction);
                }
                continue;
            }

            var violations = ReportValidator.Validate(result!);
            if (violations.Count == 0)
            {
                logger.LogInformation(
                    "Job {JobId} synthesis: risk {RiskScore:F1} ({Severity}, {TechniqueCount} techniques, attempt {Attempt})",
                    job.Id, result!.RiskScore, result.Severity, result.MitreTechniques.Count, attempt);
                return result;
            }

            logger.LogWarning("Synthesis report rejected by validator (attempt {Attempt}/{Max}): {Violations}",
                attempt, MaxAttempts, string.Join(" | ", violations));
            if (attempt < MaxAttempts)
            {
                history.AddAssistantMessage(text ?? string.Empty);
                history.AddUserMessage(SynthesisPrompts.BuildValidationRetryInstruction(violations));
            }
        }

        throw new LlmResponseFormatException(
            $"Synthesis LLM response did not satisfy the report contract after {MaxAttempts} attempts.");
    }

    /// <summary>Builds the evidence bundle from the database (IOCs, intel, CloudTrail correlation).</summary>
    private async Task<SynthesisEvidence> GatherEvidenceAsync(
        AnalysisJob job, EmailAnalysisResult? emailAnalysis, CancellationToken cancellationToken)
    {
        var ruleData = job.Tier1Result is null
            ? null
            : RuleIocSeeder.TryReadReport(job.Tier1Result.RuleCheckResults);

        var iocs = await db.Iocs.AsNoTracking()
            .Where(i => i.JobId == job.Id)
            .Include(i => i.IntelResults)
            .ToListAsync(cancellationToken);

        var ipValues = iocs.Where(i => i.Type == IocType.Ip).Select(i => i.Value).ToList();
        var cloudtrailEvents = ipValues.Count == 0
            ? []
            : await db.CloudtrailLogs.AsNoTracking()
                .Where(l => l.SourceIp != null && ipValues.Contains(l.SourceIp))
                .OrderByDescending(l => l.EventTime)
                .Take(MaxCloudtrailEvents)
                .ToListAsync(cancellationToken);

        return new SynthesisEvidence
        {
            FileName = job.FileName,
            ArtifactType = job.FileType.ToString(),
            Tier1Verdict = job.Tier1Result?.Verdict.ToString() ?? "Unknown",
            Tier1RuleScore = ruleData?.RiskScore ?? 0,
            MatchedRules = ruleData?.MatchedRules ?? [],
            MlScore = job.Tier1Result?.MlScore,
            Iocs = iocs.Select(i => new IocEvidence(
                i.Type.ToString(),
                i.Value,
                i.ExtractedBy.ToString(),
                i.IntelResults
                    .Select(r => new IntelEvidence(r.Source.ToString(), r.MaliciousScore, r.FromLiveApi))
                    .ToList())).ToList(),
            EmailAnalysis = emailAnalysis,
            CloudtrailEvents = cloudtrailEvents
                .Select(e => new CloudtrailEvidence(
                    e.EventTime, e.EventName, e.SourceIp, e.UserIdentity, e.AwsRegion))
                .ToList()
        };
    }
}
