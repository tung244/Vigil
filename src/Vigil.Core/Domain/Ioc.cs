namespace Vigil.Core.Domain;

/// <summary>Indicator of Compromise extracted from an artifact.</summary>
public class Ioc
{
    public Guid Id { get; set; }
    public Guid JobId { get; set; }
    public AnalysisJob Job { get; set; } = null!;

    public IocType Type { get; set; }
    public required string Value { get; set; }

    /// <summary>Rule-based extraction or LLM extraction.</summary>
    public IocExtractor ExtractedBy { get; set; }

    public List<ThreatIntelResult> IntelResults { get; set; } = [];
}
