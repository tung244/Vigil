using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>LLM verdict for an email artifact.</summary>
public enum EmailVerdict
{
    Phishing,
    Suspicious,
    Safe
}

/// <summary>One IOC reported by the LLM email analyst.</summary>
public sealed record ExtractedIoc(IocType Type, string Value);

/// <summary>
/// Structured output of the Email Analyst stage, parsed from the LLM's JSON
/// response (see <see cref="EmailAnalystPrompts"/> for the contract). Kept
/// in-memory; Step 8 (synthesis) persists it into the report evidence trail.
/// </summary>
public sealed class EmailAnalysisResult
{
    public required EmailVerdict Status { get; init; }

    /// <summary>LLM self-reported confidence, 0.0–1.0.</summary>
    public double Confidence { get; init; } = 0.5;

    /// <summary>IOCs the LLM found; unknown types are dropped during parsing.</summary>
    public IReadOnlyList<ExtractedIoc> Iocs { get; init; } = [];

    /// <summary>Short phishing indicator strings, e.g. "urgency language".</summary>
    public IReadOnlyList<string> PhishingIndicators { get; init; } = [];

    public required string Summary { get; init; }
}
