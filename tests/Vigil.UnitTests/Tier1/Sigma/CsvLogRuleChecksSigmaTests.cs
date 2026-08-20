using Vigil.Core.Domain;
using Vigil.Core.Tier1;
using Vigil.Core.Tier1.Sigma;
using Xunit;

namespace Vigil.UnitTests.Tier1.Sigma;

/// <summary>Integration of the Sigma engine into CsvLogRuleChecks.</summary>
public sealed class CsvLogRuleChecksSigmaTests : IDisposable
{
    private readonly string _ruleDir =
        Path.Combine(Path.GetTempPath(), $"vigil-sigma-csv-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_ruleDir))
        {
            Directory.Delete(_ruleDir, recursive: true);
        }
    }

    private SigmaEngine WriteRule(string yaml)
    {
        Directory.CreateDirectory(_ruleDir);
        File.WriteAllText(Path.Combine(_ruleDir, "rule.yml"), yaml);
        return SigmaEngine.LoadFromDirectory(_ruleDir);
    }

    private const string TamperRule = """
        title: AWS CloudTrail Logging Disabled or Tampered
        level: critical
        detection:
          selection:
            eventSource: cloudtrail.amazonaws.com
            eventName:
              - StopLogging
              - DeleteTrail
          condition: selection
        """;

    private const string CsvWithStopLogging = """
        eventTime,eventName,eventSource,sourceIPAddress,userIdentityuserName,errorCode
        2026-03-23T09:00:00Z,StopLogging,cloudtrail.amazonaws.com,203.0.113.9,attacker,
        2026-03-23T09:01:00Z,GetObject,s3.amazonaws.com,203.0.113.9,attacker,
        """;

    [Fact]
    public void Matching_sigma_rule_lands_in_matched_rules_and_escalates()
    {
        var engine = WriteRule(TamperRule);

        var report = CsvLogRuleChecks.Analyze(CsvWithStopLogging, engine);

        Assert.Contains("sigma:aws_cloudtrail_logging_disabled_or_tampered", report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
        Assert.Equal(1, report.Extracted["sigmaRulesLoaded"]);

        var check = Assert.Single(report.Checks, c => c.Name == "sigma_rules");
        Assert.Equal("flag", check.Result);
        Assert.Contains("critical", check.Detail);
    }

    [Fact]
    public void Empty_engine_is_a_clean_noop()
    {
        var report = CsvLogRuleChecks.Analyze(CsvWithStopLogging, SigmaEngine.Empty);

        Assert.DoesNotContain(report.MatchedRules, r => r.StartsWith("sigma:", StringComparison.Ordinal));
        Assert.Equal(0, report.Extracted["sigmaRulesLoaded"]);

        var check = Assert.Single(report.Checks, c => c.Name == "sigma_rules");
        Assert.Equal("pass", check.Result);
        Assert.Equal("No rules loaded.", check.Detail);
    }

    [Fact]
    public void Rules_loaded_but_no_match_reports_pass()
    {
        var engine = WriteRule(TamperRule);

        const string benign = """
            eventTime,eventName,eventSource,sourceIPAddress,userIdentityuserName,errorCode
            2026-03-23T09:00:00Z,GetObject,s3.amazonaws.com,10.0.0.1,u01,
            2026-03-23T09:01:00Z,PutObject,s3.amazonaws.com,10.0.0.1,u01,
            """;

        var report = CsvLogRuleChecks.Analyze(benign, engine);

        Assert.DoesNotContain(report.MatchedRules, r => r.StartsWith("sigma:", StringComparison.Ordinal));
        var check = Assert.Single(report.Checks, c => c.Name == "sigma_rules");
        Assert.Equal("pass", check.Result);
        Assert.Contains("No match across 1 loaded rules.", check.Detail);
    }
}
