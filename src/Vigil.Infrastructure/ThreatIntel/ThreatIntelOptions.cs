namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// Config section "ThreatIntel". Empty API keys are supported: the clients
/// then short-circuit to the heuristic fallback without any HTTP call.
/// </summary>
public sealed class ThreatIntelOptions
{
    public string VirusTotalApiKey { get; set; } = "";
    public string AbuseIpDbApiKey { get; set; } = "";

    /// <summary>How long a stored ThreatIntelResult counts as fresh cache.</summary>
    public int CacheHours { get; set; } = 24;
}
