namespace Vigil.Core.Domain;

/// <summary>
/// One uploaded artifact moving through the analysis pipeline.
/// The dashboard polls this row to show live progress.
/// </summary>
public class AnalysisJob
{
    public Guid Id { get; set; }
    public required string FileName { get; set; }
    public ArtifactType FileType { get; set; }
    public JobStatus Status { get; set; } = JobStatus.Queued;

    /// <summary>Where the uploaded artifact is stored on disk.</summary>
    public required string StoragePath { get; set; }

    /// <summary>Human-readable pipeline step, e.g. "tier1.pii_scrub".</summary>
    public string? CurrentStep { get; set; }
    public string? ErrorMessage { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }

    public Tier1Result? Tier1Result { get; set; }
    public List<Ioc> Iocs { get; set; } = [];
    public AnalysisReport? Report { get; set; }
}
