using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>One report claim linked to the concrete evidence source that supports it.</summary>
public sealed record EvidenceItem(string Claim, string Source);

/// <summary>
/// Structured output of the Synthesis stage (Step 8), parsed from the LLM's
/// JSON response (see <see cref="SynthesisPrompts"/> for the contract) or
/// built deterministically by <see cref="DeterministicSynthesis"/> when no LLM
/// is configured. Persisted as one <see cref="AnalysisReport"/> row per job.
/// </summary>
public sealed class SynthesisResult
{
    /// <summary>0.0–10.0 risk score; the severity band is derived from it (<see cref="ReportValidator.SeverityForScore"/>).</summary>
    public required double RiskScore { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>Analyst-facing markdown summary. Fallback reports start with "[generated without LLM]".</summary>
    public required string SummaryMarkdown { get; init; }

    /// <summary>MITRE ATT&amp;CK technique IDs, e.g. ["T1566", "T1566.002"].</summary>
    public required IReadOnlyList<string> MitreTechniques { get; init; }

    public required IReadOnlyList<string> RecommendedActions { get; init; }

    /// <summary>Every claim linked to its source (rule name, IOC lookup, ml_score, ...). Never empty.</summary>
    public required IReadOnlyList<EvidenceItem> EvidenceTrail { get; init; }
}
