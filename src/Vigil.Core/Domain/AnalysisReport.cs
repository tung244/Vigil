namespace Vigil.Core.Domain;

/// <summary>Final synthesized incident report, one per job.</summary>
public class AnalysisReport
{
    public Guid Id { get; set; }
    public Guid JobId { get; set; }
    public AnalysisJob Job { get; set; } = null!;

    public double RiskScore { get; set; }
    public Severity Severity { get; set; }

    /// <summary>LLM-written analyst-facing summary.</summary>
    public required string SummaryMarkdown { get; set; }

    /// <summary>JSON array of MITRE ATT&amp;CK technique IDs, e.g. ["T1566.001"].</summary>
    public required string MitreTechniques { get; set; }

    /// <summary>JSON array of recommended response actions.</summary>
    public required string RecommendedActions { get; set; }

    /// <summary>JSON: every claim linked to the tool output that supports it.</summary>
    public required string EvidenceTrail { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public IncidentEmbedding? Embedding { get; set; }
}
