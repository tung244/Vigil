namespace Vigil.Core.Domain;

/// <summary>
/// Output of the cheap pre-LLM filter. Kept for auditability:
/// "why did the system drop/escalate this event?"
/// </summary>
public class Tier1Result
{
    public Guid Id { get; set; }
    public Guid JobId { get; set; }
    public AnalysisJob Job { get; set; } = null!;

    /// <summary>Artifact content after PII redaction (what the LLM would have seen).</summary>
    public required string ScrubbedPayload { get; set; }

    /// <summary>JSON: rule check outcomes (SPF/DKIM, lookalike domain, ...).</summary>
    public required string RuleCheckResults { get; set; }

    /// <summary>ONNX phishing classifier score 0.0–1.0; null for non-email artifacts.</summary>
    public double? MlScore { get; set; }

    public Tier1Verdict Verdict { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
