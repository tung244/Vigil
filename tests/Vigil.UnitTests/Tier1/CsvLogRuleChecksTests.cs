using System.Text;
using Vigil.Core.Domain;
using Vigil.Core.Tier1;
using Xunit;

namespace Vigil.UnitTests.Tier1;

public class CsvLogRuleChecksTests
{
    private const string Header =
        "eventTime,eventName,eventSource,sourceIPAddress,userIdentityuserName,errorCode,userAgent";

    private static string Row(
        string eventName, string user, string ip,
        string errorCode = "", string time = "2026-03-23T10:00:00Z") =>
        $"{time},{eventName},iam.amazonaws.com,{ip},{user},{errorCode},console";

    private static string Csv(params string[] rows) => Header + "\n" + string.Join("\n", rows);

    /// <summary>Builds a batch of <paramref name="normalUsers"/> users with
    /// <paramref name="eventsPerUser"/> benign events each, plus one heavy user
    /// with <paramref name="heavyEvents"/> benign events.</summary>
    private static string FrequencyBatch(int normalUsers, int eventsPerUser, int heavyEvents)
    {
        var sb = new StringBuilder(Header).Append('\n');
        for (var u = 1; u <= normalUsers; u++)
        {
            for (var e = 0; e < eventsPerUser; e++)
            {
                sb.AppendLine(Row("GetObject", $"user{u:D2}", $"10.0.0.{u}"));
            }
        }

        for (var e = 0; e < heavyEvents; e++)
        {
            sb.AppendLine(Row("GetObject", "heavy", "10.0.9.9"));
        }

        return sb.ToString();
    }

    [Fact]
    public void Empty_content_is_benign()
    {
        var report = CsvLogRuleChecks.Analyze(string.Empty);

        Assert.Equal(Tier1Verdict.Benign, report.Verdict);
        Assert.Empty(report.MatchedRules);
        Assert.Equal(0, report.Extracted["recordCount"]);
    }

    [Fact]
    public void Benign_batch_produces_no_rules()
    {
        var report = CsvLogRuleChecks.Analyze(Csv(
            Row("GetObject", "alice", "10.0.0.1"),
            Row("ListBuckets", "alice", "10.0.0.1"),
            Row("GetObject", "bob", "10.0.0.2"),
            Row("DescribeInstances", "bob", "10.0.0.2")));

        Assert.Equal(Tier1Verdict.Benign, report.Verdict);
        Assert.Empty(report.MatchedRules);
        Assert.Equal(4, report.Extracted["recordCount"]);
        Assert.Equal(2, report.Extracted["userCount"]);
    }

    [Fact]
    public void Flags_high_risk_api_calls()
    {
        var report = CsvLogRuleChecks.Analyze(Csv(
            Row("GetObject", "alice", "10.0.0.1"),
            Row("StopLogging", "alice", "10.0.0.1"),
            Row("DeleteTrail", "alice", "10.0.0.1")));

        Assert.Contains("high_risk_api:StopLogging", report.MatchedRules);
        Assert.Contains("high_risk_api:DeleteTrail", report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public void Flags_access_denied()
    {
        var report = CsvLogRuleChecks.Analyze(Csv(
            Row("ListBuckets", "backup", "10.0.0.9", errorCode: "AccessDenied")));

        Assert.Contains("access_denied:ListBuckets", report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public void Recon_burst_requires_a_single_user()
    {
        var burst = CsvLogRuleChecks.Analyze(Csv(
            Row("ListBuckets", "mallory", "10.0.0.5"),
            Row("ListUsers", "mallory", "10.0.0.5"),
            Row("GetAccountAuthorizationDetails", "mallory", "10.0.0.5")));

        Assert.Contains(burst.MatchedRules, r => r.StartsWith("recon_burst:mallory:3", StringComparison.Ordinal));

        // Same events spread across three users is not a burst.
        var spread = CsvLogRuleChecks.Analyze(Csv(
            Row("ListBuckets", "alice", "10.0.0.1"),
            Row("ListUsers", "bob", "10.0.0.2"),
            Row("ListRoles", "carol", "10.0.0.3")));

        Assert.DoesNotContain(spread.MatchedRules,
            r => r.StartsWith("recon_burst:", StringComparison.Ordinal));
    }

    [Fact]
    public void Flags_frequency_spike_above_median_floor()
    {
        // 9 users × 2 events + 1 user × 20 events: median 2, spike floor max(15, 10) = 15.
        var report = CsvLogRuleChecks.Analyze(FrequencyBatch(normalUsers: 9, eventsPerUser: 2, heavyEvents: 20));

        Assert.Contains(report.MatchedRules,
            r => r.StartsWith("user_event_frequency_spike:heavy:", StringComparison.Ordinal));
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public void Flags_zscore_outlier_when_sample_is_large_enough()
    {
        // 11 users × 2 events + 1 user × 50 events → z ≈ 3.3 for the heavy user.
        var report = CsvLogRuleChecks.Analyze(FrequencyBatch(normalUsers: 11, eventsPerUser: 2, heavyEvents: 50));

        Assert.Contains(report.MatchedRules,
            r => r.StartsWith("user_event_count_anomaly:heavy:z=", StringComparison.Ordinal));
    }

    [Fact]
    public void Does_not_flag_evenly_distributed_activity()
    {
        var report = CsvLogRuleChecks.Analyze(FrequencyBatch(normalUsers: 12, eventsPerUser: 3, heavyEvents: 0));

        Assert.DoesNotContain(report.MatchedRules,
            r => r.StartsWith("user_event_count_anomaly:", StringComparison.Ordinal)
                || r.StartsWith("user_event_frequency_spike:", StringComparison.Ordinal)
                || r.StartsWith("ip_event_count_anomaly:", StringComparison.Ordinal)
                || r.StartsWith("ip_event_frequency_spike:", StringComparison.Ordinal));
    }

    [Fact]
    public void Flags_sensitive_event_from_unseen_ip()
    {
        var report = CsvLogRuleChecks.Analyze(Csv(
            Row("GetObject", "backup", "10.0.0.99"),
            Row("GetObject", "backup", "10.0.0.99"),
            Row("AssumeRole", "backup", "203.0.113.50")));

        Assert.Contains("sensitive_event_unseen_ip:AssumeRole:backup:203.0.113.50", report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public void Sensitive_event_from_usual_ip_is_not_flagged()
    {
        var report = CsvLogRuleChecks.Analyze(Csv(
            Row("GetObject", "backup", "10.0.0.99"),
            Row("AssumeRole", "backup", "10.0.0.99")));

        // AssumeRole is still a high-risk API, but the unseen-IP rule stays quiet.
        Assert.DoesNotContain(report.MatchedRules,
            r => r.StartsWith("sensitive_event_unseen_ip:", StringComparison.Ordinal));
    }

    [Fact]
    public void Tolerates_truncated_rows_and_unknown_columns()
    {
        // Mirrors the historical dec12 dataset: rows shorter than the header.
        var content = Header + "\n"
            + "3038ebd2,2017-02,255.253\n" // only 3 of 7 columns
            + Row("GetObject", "alice", "10.0.0.1");

        var records = CsvLogParser.Parse(content);

        Assert.Equal(2, records.Count);
        // Truncated row: fields map positionally, the rest stay empty.
        Assert.Equal("2017-02", records[0].EventName);
        Assert.Equal(string.Empty, records[0].SourceIp);
        Assert.Equal(string.Empty, records[0].UserName);

        var report = CsvLogRuleChecks.Analyze(content);
        Assert.Equal(2, report.Extracted["recordCount"]);
    }

    [Fact]
    public void Parses_quoted_fields_with_commas()
    {
        var content = Header + "\n"
            + "2026-03-23T10:00:00Z,GetObject,s3.amazonaws.com,10.0.0.1,alice,,\"Console, Web\"";

        var records = CsvLogParser.Parse(content);

        Assert.Single(records);
        Assert.Equal("Console, Web", records[0].UserAgent);
    }
}
