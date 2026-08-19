namespace Vigil.Core.Tier2;

/// <summary>One threat intel lookup attached to an IOC (live API or heuristic fallback).</summary>
public sealed record IntelEvidence(string Source, double MaliciousScore, bool FromLiveApi);

/// <summary>One extracted IOC with all of its threat intel lookups.</summary>
public sealed record IocEvidence(
    string Type,
    string Value,
    string ExtractedBy,
    IReadOnlyList<IntelEvidence> Intel);

/// <summary>CloudTrail activity correlated with an IOC source IP.</summary>
public sealed record CloudtrailEvidence(
    DateTimeOffset EventTime,
    string EventName,
    string? SourceIp,
    string? UserIdentity,
    string? AwsRegion);

/// <summary>
/// One past incident retrieved by pgvector embedding similarity (RAG context
/// for the synthesis prompt). <see cref="SummaryExcerpt"/> is already
/// truncated; <see cref="Similarity"/> is cosine similarity in [0, 1].
/// </summary>
public sealed record SimilarIncidentEvidence(
    Guid ReportId,
    double RiskScore,
    string Severity,
    IReadOnlyList<string> MatchedRules,
    string SummaryExcerpt,
    double Similarity);

/// <summary>
/// The complete evidence bundle for one job, gathered from the database before
/// synthesis. This is the only input the synthesis prompt (and the
/// deterministic fallback) may reason about — the "evidence discipline" port
/// of the old <c>synthesis.py</c>: every report claim must trace back to a
/// field of this bundle.
/// </summary>
public sealed record SynthesisEvidence
{
    public required string FileName { get; init; }
    public required string ArtifactType { get; init; }

    /// <summary>Tier 1 verdict string ("Benign" / "Suspicious").</summary>
    public required string Tier1Verdict { get; init; }

    /// <summary>Explainable Tier 1 rule score, 0–100.</summary>
    public required int Tier1RuleScore { get; init; }

    /// <summary>Stable rule identifiers Tier 1 matched, e.g. "spf_fail", "recon_burst:alice:4".</summary>
    public required IReadOnlyList<string> MatchedRules { get; init; }

    /// <summary>ONNX phishing classifier score 0.0–1.0; null for non-email artifacts.</summary>
    public double? MlScore { get; init; }

    public required IReadOnlyList<IocEvidence> Iocs { get; init; }

    /// <summary>LLM email analyst output; null for non-email artifacts or when that stage did not run.</summary>
    public EmailAnalysisResult? EmailAnalysis { get; init; }

    /// <summary>CloudTrail events whose source IP matches an IOC; empty when there is no correlation.</summary>
    public required IReadOnlyList<CloudtrailEvidence> CloudtrailEvents { get; init; }

    /// <summary>
    /// Past incidents retrieved by pgvector embedding similarity; empty when
    /// embeddings are disabled or nothing similar exists. Not serialized into
    /// the evidence JSON — the prompt renders it via
    /// <see cref="SynthesisPrompts.BuildSimilarIncidentsSection"/> instead.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<SimilarIncidentEvidence> SimilarIncidents { get; init; } = [];
}
