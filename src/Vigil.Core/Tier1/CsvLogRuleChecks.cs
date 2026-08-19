using Vigil.Core.Domain;

namespace Vigil.Core.Tier1;

/// <summary>One parsed CSV log row; missing columns become empty strings.</summary>
public sealed record CsvLogRecord
{
    public string EventTime { get; init; } = string.Empty;
    public string EventName { get; init; } = string.Empty;
    public string SourceIp { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string ErrorCode { get; init; } = string.Empty;
    public string ErrorMessage { get; init; } = string.Empty;
    public string UserAgent { get; init; } = string.Empty;
}

/// <summary>
/// Tier 1 statistical anomaly rules for CSV log batches (CloudTrail-style).
/// Deliberate replacement for the old system's Isolation Forest / LSTM UBA:
/// explainable frequency statistics (z-score, median spike) plus known-bad
/// event rules ported from <c>forensic_analyst/tier1_filter.py</c>.
/// </summary>
public static class CsvLogRuleChecks
{
    /// <summary>Minimum z-score for a per-user/per-IP event count to be anomalous.</summary>
    public const double ZScoreThreshold = 3.0;

    /// <summary>Event counts at or above max(15, 5 × median) are frequency spikes.</summary>
    public const int SpikeAbsoluteFloor = 15;
    public const double SpikeMedianFactor = 5.0;

    /// <summary>Recon events from a single user at or above this count form a burst.</summary>
    public const int ReconBurstThreshold = 3;

    /// <summary>Ported from the old system's high-risk CloudTrail event list.</summary>
    private static readonly HashSet<string> HighRiskEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "AssumeRole", "CreateUser", "CreateAccessKey", "AttachUserPolicy",
        "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
        "CreateLoginProfile", "UpdateLoginProfile", "DeleteTrail",
        "StopLogging", "UpdateTrail", "PutEventSelectors",
        "DisableKey", "ScheduleKeyDeletion",
        "AuthorizeSecurityGroupIngress", "CreateSecurityGroup",
        "DeleteFlowLogs", "DeleteBucket", "PutBucketPolicy",
        "ConsoleLogin",
    };

    private static readonly HashSet<string> ReconEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "ListBuckets", "ListUsers", "ListRoles", "ListAccessKeys",
        "DescribeInstances", "DescribeSecurityGroups", "GetBucketAcl",
        "ListAttachedUserPolicies", "ListGroupsForUser",
        "GetAccountAuthorizationDetails",
    };

    /// <summary>Events that are especially alarming from an IP the user never used before.</summary>
    private static readonly HashSet<string> SensitiveEvents = new(StringComparer.OrdinalIgnoreCase)
    {
        "ConsoleLogin", "AssumeRole", "CreateAccessKey", "CreateLoginProfile",
    };

    public static Tier1RuleReport Analyze(string csvContent)
    {
        var records = CsvLogParser.Parse(csvContent);
        var report = new Tier1RuleReport
        {
            ArtifactType = ArtifactType.Csv.ToString(),
            Verdict = Tier1Verdict.Benign
        };

        report.Extracted["recordCount"] = records.Count;
        if (records.Count == 0)
        {
            report.Checks.Add(new RuleCheck("parse", "info", "No data rows found."));
            report.ApplyVerdict();
            return report;
        }

        var users = records.Where(r => r.UserName.Length > 0).Select(r => r.UserName).Distinct().ToList();
        var ips = records.Where(r => r.SourceIp.Length > 0).Select(r => r.SourceIp).Distinct().ToList();
        report.Extracted["userCount"] = users.Count;
        report.Extracted["uniqueIps"] = ips;

        // 1. High-risk API calls (deduplicated by event name).
        var highRisk = records.Select(r => r.EventName)
            .Where(HighRiskEvents.Contains).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var name in highRisk)
        {
            report.MatchedRules.Add($"high_risk_api:{name}");
        }

        report.Checks.Add(new RuleCheck("high_risk_api",
            highRisk.Count > 0 ? "flag" : "pass",
            highRisk.Count > 0 ? $"High-risk events: {string.Join(", ", highRisk)}" : "None found."));

        // 2. Access denied errors (possible probing).
        var denied = records
            .Where(r => r.ErrorCode.Contains("AccessDenied", StringComparison.OrdinalIgnoreCase)
                || r.ErrorMessage.Equals("Access Denied", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.EventName)
            .Where(n => n.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var name in denied)
        {
            report.MatchedRules.Add($"access_denied:{name}");
        }

        report.Checks.Add(new RuleCheck("access_denied",
            denied.Count > 0 ? "flag" : "pass",
            denied.Count > 0 ? $"Access denied on: {string.Join(", ", denied)}" : "None found."));

        // 3. Recon burst: many reconnaissance calls by a single user.
        var reconByUser = records.Where(r => ReconEvents.Contains(r.EventName))
            .GroupBy(r => r.UserName)
            .Where(g => g.Count() >= ReconBurstThreshold)
            .ToList();
        foreach (var group in reconByUser)
        {
            report.MatchedRules.Add($"recon_burst:{group.Key}:{group.Count()}");
        }

        report.Checks.Add(new RuleCheck("recon_burst",
            reconByUser.Count > 0 ? "flag" : "pass",
            reconByUser.Count > 0
                ? string.Join("; ", reconByUser.Select(g => $"{g.Key} made {g.Count()} recon calls"))
                : "No per-user recon burst."));

        // 4. Frequency anomalies: z-score and median spike per user and per IP.
        FlagFrequencyAnomalies(records.GroupBy(r => r.UserName).Where(g => g.Key.Length > 0),
            "user", report);
        FlagFrequencyAnomalies(records.GroupBy(r => r.SourceIp).Where(g => g.Key.Length > 0),
            "ip", report);

        // 5. Sensitive event from an IP the user never used elsewhere in the batch.
        var ipsByUser = records.Where(r => r.UserName.Length > 0 && r.SourceIp.Length > 0)
            .GroupBy(r => r.UserName)
            .ToDictionary(g => g.Key, g => g.Select(r => r.SourceIp).ToHashSet(), StringComparer.Ordinal);
        var sensitiveFlags = records
            .Where(r => SensitiveEvents.Contains(r.EventName) && r.UserName.Length > 0 && r.SourceIp.Length > 0)
            .Where(r => ipsByUser.TryGetValue(r.UserName, out var userIps)
                && userIps.Count > 1 // the user has a baseline of other IPs in this batch
                && records.Count(o => o.UserName == r.UserName && o.SourceIp == r.SourceIp
                    && !SensitiveEvents.Contains(o.EventName)) == 0)
            .Select(r => $"sensitive_event_unseen_ip:{r.EventName}:{r.UserName}:{r.SourceIp}")
            .Distinct()
            .ToList();
        foreach (var flag in sensitiveFlags)
        {
            report.MatchedRules.Add(flag);
        }

        report.Checks.Add(new RuleCheck("sensitive_event_unseen_ip",
            sensitiveFlags.Count > 0 ? "flag" : "pass",
            sensitiveFlags.Count > 0
                ? $"{sensitiveFlags.Count} sensitive event(s) from previously unseen IPs."
                : "None found."));

        // Explainable score: 15 points per rule family that fired, capped at 100.
        var families = report.MatchedRules
            .Select(r => r.Split(':')[0])
            .Distinct()
            .Count();
        report.RiskScore = Math.Min(families * 15, 100);

        report.ApplyVerdict();
        return report;
    }

    private static void FlagFrequencyAnomalies(
        IEnumerable<IGrouping<string, CsvLogRecord>> groups, string dimension, Tier1RuleReport report)
    {
        var counts = groups.Select(g => (Key: g.Key, Count: g.Count()))
            .OrderBy(x => x.Key, StringComparer.Ordinal)
            .ToList();
        if (counts.Count < 2)
        {
            return;
        }

        var values = counts.Select(c => (double)c.Count).ToList();
        var mean = values.Average();
        var std = Math.Sqrt(values.Sum(v => (v - mean) * (v - mean)) / values.Count);
        var median = values.OrderBy(v => v).ElementAt(values.Count / 2);
        var spikeFloor = Math.Max(SpikeAbsoluteFloor, SpikeMedianFactor * median);

        var flagged = new List<string>();
        foreach (var (key, count) in counts)
        {
            var z = std > 0 ? (count - mean) / std : 0.0;
            if (z >= ZScoreThreshold)
            {
                var rule = $"{dimension}_event_count_anomaly:{key}:z={z:F2}";
                report.MatchedRules.Add(rule);
                flagged.Add(rule);
            }
            else if (count >= spikeFloor)
            {
                var rule = $"{dimension}_event_frequency_spike:{key}:count={count}";
                report.MatchedRules.Add(rule);
                flagged.Add(rule);
            }
        }

        report.Checks.Add(new RuleCheck($"{dimension}_frequency",
            flagged.Count > 0 ? "flag" : "pass",
            $"{counts.Count} {dimension}(s), mean={mean:F1}, std={std:F2}, median={median:F0}, spike floor={spikeFloor:F0}."
            + (flagged.Count > 0 ? $" Flagged: {string.Join(", ", flagged)}" : string.Empty)));
    }
}
