namespace Vigil.Core.Domain;

/// <summary>
/// One lookup of an IOC against a threat intel source.
/// Doubles as a cache: LookedUpAt is checked before hitting the API again
/// (VirusTotal free tier is 4 req/min).
/// </summary>
public class ThreatIntelResult
{
    public Guid Id { get; set; }
    public Guid IocId { get; set; }
    public Ioc Ioc { get; set; } = null!;

    public ThreatIntelSource Source { get; set; }

    /// <summary>JSON: raw API response (or the heuristic fallback payload).</summary>
    public required string RawResponse { get; set; }

    /// <summary>Normalized 0.0–1.0 maliciousness score.</summary>
    public double MaliciousScore { get; set; }

    /// <summary>False when the heuristic fallback was used instead of the live API.</summary>
    public bool FromLiveApi { get; set; }

    public DateTimeOffset LookedUpAt { get; set; } = DateTimeOffset.UtcNow;
}
