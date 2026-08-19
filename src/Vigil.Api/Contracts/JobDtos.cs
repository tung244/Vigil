using System.Text.Json;
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
    string? ErrorMessage,
    bool HasReport)
{
    public static JobSummary From(AnalysisJob job, bool hasReport) => new(
        job.Id,
        job.FileName,
        job.FileType.ToString().ToLowerInvariant(),
        job.Status.ToString(),
        job.CurrentStep,
        job.CreatedAt,
        job.StartedAt,
        job.FinishedAt,
        job.ErrorMessage,
        hasReport);
}

public record JobListResponse(IReadOnlyList<JobSummary> Items, int Total, int Page, int PageSize);

public record EvidenceItemResponse(string Claim, string Source);

/// <summary>
/// The persisted analysis report with the jsonb columns parsed back into real
/// arrays. Severity is lowercase ("low".."critical") to match the synthesis
/// contract; RiskScore is 0–10.
/// </summary>
public record ReportResponse(
    Guid JobId,
    double RiskScore,
    string Severity,
    string SummaryMarkdown,
    IReadOnlyList<string> MitreTechniques,
    IReadOnlyList<string> RecommendedActions,
    IReadOnlyList<EvidenceItemResponse> EvidenceTrail,
    DateTimeOffset CreatedAt)
{
    public static ReportResponse From(AnalysisReport report) => new(
        report.JobId,
        report.RiskScore,
        report.Severity.ToString().ToLowerInvariant(),
        report.SummaryMarkdown,
        ParseArray<string>(report.MitreTechniques),
        ParseArray<string>(report.RecommendedActions),
        ParseArray<EvidenceItemResponse>(report.EvidenceTrail),
        report.CreatedAt);

    /// <summary>Stored jsonb → array; corrupt payloads degrade to an empty array.</summary>
    private static IReadOnlyList<T> ParseArray<T>(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<List<T>>(json, JsonOptions) ?? [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };
}
