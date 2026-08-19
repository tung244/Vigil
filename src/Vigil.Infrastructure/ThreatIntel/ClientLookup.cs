namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// Outcome of one external threat intel API call. Clients never throw for
/// API/network problems — they return <see cref="Fail"/> with a machine
/// readable reason so the service can fall back to heuristic scoring.
/// </summary>
public sealed record ClientLookup(bool Success, double Score, string RawJson, string? FailureReason)
{
    public static ClientLookup Ok(double score, string rawJson) => new(true, score, rawJson, null);

    public static ClientLookup Fail(string reason) => new(false, 0.0, "", reason);
}
