using Vigil.Core.Domain;

namespace Vigil.Api.Contracts;

public record JobAcceptedResponse(Guid JobId, string Status);

public record JobSummary(
    Guid Id,
    string FileName,
    string FileType,
    string Status,
    string? CurrentStep,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? FinishedAt,
    string? ErrorMessage)
{
    public static JobSummary From(AnalysisJob job) => new(
        job.Id,
        job.FileName,
        job.FileType.ToString().ToLowerInvariant(),
        job.Status.ToString(),
        job.CurrentStep,
        job.CreatedAt,
        job.StartedAt,
        job.FinishedAt,
        job.ErrorMessage);
}

public record JobListResponse(IReadOnlyList<JobSummary> Items, int Total, int Page, int PageSize);
