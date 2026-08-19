namespace Vigil.Core.Domain;

public enum JobStatus
{
    Queued,
    Filtering,
    Analyzing,
    Done,
    Failed
}

public enum ArtifactType
{
    Eml,
    Csv,
    Json
}

public enum Tier1Verdict
{
    Benign,
    Suspicious
}

public enum IocType
{
    Ip,
    Domain,
    Url,
    Hash,
    Email
}

public enum IocExtractor
{
    Rule,
    Llm
}

public enum ThreatIntelSource
{
    VirusTotal,
    AbuseIpDb
}

public enum Severity
{
    Low,
    Medium,
    High,
    Critical
}
