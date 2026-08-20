using System.Text.Json.Serialization;

namespace Vigil.Api.Contracts;

/// <summary>KPI summary for the dashboard header cards.</summary>
public record StatsResponse(
    int TotalJobs,
    int TotalReports,
    JobsByStatusResponse JobsByStatus,
    ReportsBySeverityResponse ReportsBySeverity,
    double AvgRiskScore,
    [property: JsonPropertyName("last24hJobs")] int Last24HJobs);

/// <summary>Job counts bucketed by pipeline status.</summary>
public record JobsByStatusResponse(int Queued, int Filtering, int Analyzing, int Done, int Failed);

/// <summary>Report counts bucketed by severity.</summary>
public record ReportsBySeverityResponse(int Low, int Medium, int High, int Critical);

/// <summary>One MITRE ATT&amp;CK technique with its frequency across all reports.</summary>
public record MitreTechniqueStat(string TechniqueId, string Tactic, int Count);

/// <summary>
/// Heatmap payload: per-technique counts plus the distinct tactics present,
/// in ATT&amp;CK kill-chain order so the frontend can lay out the grid.
/// </summary>
public record MitreHeatmapResponse(
    IReadOnlyList<MitreTechniqueStat> Techniques,
    IReadOnlyList<string> Tactics);
