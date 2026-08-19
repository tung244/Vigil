using Vigil.Core.Domain;

namespace Vigil.Core.ThreatIntel;

/// <summary>
/// Enriches an IOC with threat intel. Checks the DB cache first (per
/// Type/Value/Source, fresh within the configured CacheHours), then calls the
/// live API, and falls back to heuristic scoring when the key is missing or
/// the API is unreachable. Never throws for external API failures.
/// </summary>
public interface IThreatIntelService
{
    /// <summary>
    /// Looks up one IOC against every applicable source (IP: VirusTotal +
    /// AbuseIPDB; Domain/Url/Hash: VirusTotal; Email: none → empty list).
    /// New results are persisted against an <see cref="Ioc"/> row for
    /// <paramref name="jobId"/>; cache hits return the stored row as-is.
    /// </summary>
    Task<IReadOnlyList<ThreatIntelResult>> LookupAsync(
        IocType type,
        string value,
        Guid jobId,
        IocExtractor extractedBy = IocExtractor.Rule,
        CancellationToken cancellationToken = default);
}
