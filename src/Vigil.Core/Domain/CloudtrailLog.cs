namespace Vigil.Core.Domain;

/// <summary>
/// Internal cloud activity log. Replaces AWS Athena from the original design
/// so the forensic agent can hunt locally without cloud dependencies.
/// </summary>
public class CloudtrailLog
{
    public Guid Id { get; set; }
    public DateTimeOffset EventTime { get; set; }
    public required string EventName { get; set; }
    public string? SourceIp { get; set; }
    public string? UserIdentity { get; set; }
    public string? AwsRegion { get; set; }

    /// <summary>JSON: full original event.</summary>
    public required string RawEvent { get; set; }
}
