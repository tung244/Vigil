using Pgvector;

namespace Vigil.Core.Domain;

/// <summary>
/// Vector embedding of a report summary, used to retrieve similar past
/// incidents as LLM context (RAG). Replaces Pinecone from the original design.
/// </summary>
public class IncidentEmbedding
{
    public Guid Id { get; set; }
    public Guid ReportId { get; set; }
    public AnalysisReport Report { get; set; } = null!;

    /// <summary>384-dim (MiniLM) or provider-specific embedding.</summary>
    public required Vector Embedding { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
