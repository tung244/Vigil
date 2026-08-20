using Vigil.Core.Tier1.Sigma;
using Xunit;

namespace Vigil.UnitTests.Tier1.Sigma;

/// <summary>
/// Engine-level tests: YAML parsing, field normalization, modifiers,
/// wildcards and the condition mini-language.
/// </summary>
public sealed class SigmaEngineTests : IDisposable
{
    private readonly string _ruleDir =
        Path.Combine(Path.GetTempPath(), $"vigil-sigma-tests-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_ruleDir))
        {
            Directory.Delete(_ruleDir, recursive: true);
        }
    }

    private SigmaEngine EngineWith(params (string Name, string Yaml)[] rules)
    {
        Directory.CreateDirectory(_ruleDir);
        foreach (var (name, yaml) in rules)
        {
            File.WriteAllText(Path.Combine(_ruleDir, $"{name}.yml"), yaml);
        }

        return SigmaEngine.LoadFromDirectory(_ruleDir);
    }

    private const string ConsoleLoginNoMfa = """
        title: AWS Console Login Without MFA
        id: test-id-1
        level: high
        detection:
          selection:
            eventName: ConsoleLogin
          filter_mfa:
            additionalEventData.MFAUsed: 'Yes'
          condition: selection and not filter_mfa
        """;

    [Fact]
    public void Exact_match_fires_and_condition_combines_selections()
    {
        var engine = EngineWith(("rule1", ConsoleLoginNoMfa));

        var login = new Dictionary<string, string>
        {
            ["eventname"] = "ConsoleLogin",
            ["additionaleventdatamfaused"] = "No"
        };
        var match = Assert.Single(engine.Evaluate(login));
        Assert.Equal("AWS Console Login Without MFA", match.Title);
        Assert.Equal("high", match.Level);
        Assert.Equal("aws_console_login_without_mfa", match.Slug);

        // With MFA the filter kills the match.
        var mfa = new Dictionary<string, string>
        {
            ["eventname"] = "ConsoleLogin",
            ["additionaleventdatamfaused"] = "Yes"
        };
        Assert.Empty(engine.Evaluate(mfa));
    }

    [Fact]
    public void Missing_field_never_matches()
    {
        var engine = EngineWith(("rule1", ConsoleLoginNoMfa));

        var evt = new Dictionary<string, string> { ["eventname"] = "ConsoleLogin" };
        // filter_mfa field absent → "not filter_mfa" holds → match.
        Assert.Single(engine.Evaluate(evt));

        // selection field absent → no match at all.
        Assert.Empty(engine.Evaluate(new Dictionary<string, string>()));
    }

    [Fact]
    public void List_values_are_ored_and_dotted_fields_match_flattened_headers()
    {
        const string yaml = """
            title: CloudTrail Tampered
            detection:
              selection:
                eventSource: cloudtrail.amazonaws.com
                eventName:
                  - StopLogging
                  - DeleteTrail
              condition: selection
            """;

        var engine = EngineWith(("rule1", yaml));

        // CSV header "eventSource" normalizes the same as rule field "eventSource".
        var evt = new Dictionary<string, string>
        {
            ["eventsource"] = "cloudtrail.amazonaws.com",
            ["eventname"] = "DeleteTrail"
        };
        Assert.Single(engine.Evaluate(evt));

        var other = new Dictionary<string, string>
        {
            ["eventsource"] = "cloudtrail.amazonaws.com",
            ["eventname"] = "DescribeTrails"
        };
        Assert.Empty(engine.Evaluate(other));
    }

    [Fact]
    public void Contains_modifier_and_wildcards()
    {
        const string yaml = """
            title: Open To World
            detection:
              selection:
                eventName: AuthorizeSecurityGroupIngress
              cidr:
                requestParameters.cidrIp|contains: 0.0.0.0/0
              condition: selection and cidr
            """;

        var engine = EngineWith(("rule1", yaml));

        var open = new Dictionary<string, string>
        {
            ["eventname"] = "AuthorizeSecurityGroupIngress",
            ["requestparameterscidrip"] = "0.0.0.0/0"
        };
        Assert.Single(engine.Evaluate(open));

        var closed = new Dictionary<string, string>
        {
            ["eventname"] = "AuthorizeSecurityGroupIngress",
            ["requestparameterscidrip"] = "10.0.0.0/8"
        };
        Assert.Empty(engine.Evaluate(closed));
    }

    [Fact]
    public void One_of_pattern_expands_over_matching_selections()
    {
        const string yaml = """
            title: GuardDuty Disruption
            detection:
              selection:
                eventSource: guardduty.amazonaws.com
              gd_delete:
                eventName: DeleteDetector
              gd_stop:
                eventName: StopMonitoringMembers
              condition: selection and 1 of gd_*
            """;

        var engine = EngineWith(("rule1", yaml));

        Assert.Single(engine.Evaluate(new Dictionary<string, string>
        {
            ["eventsource"] = "guardduty.amazonaws.com",
            ["eventname"] = "StopMonitoringMembers"
        }));

        // Source alone is not enough.
        Assert.Empty(engine.Evaluate(new Dictionary<string, string>
        {
            ["eventsource"] = "guardduty.amazonaws.com",
            ["eventname"] = "GetDetector"
        }));
    }

    [Fact]
    public void Wildcard_value_matches_any_non_empty_field()
    {
        const string yaml = """
            title: Root Account Usage
            detection:
              selection:
                userIdentity.type: Root
              filter_failed:
                errorCode: '*'
              condition: selection and not filter_failed
            """;

        var engine = EngineWith(("rule1", yaml));

        Assert.Single(engine.Evaluate(new Dictionary<string, string>
        {
            ["useridentitytype"] = "Root"
        }));

        Assert.Empty(engine.Evaluate(new Dictionary<string, string>
        {
            ["useridentitytype"] = "Root",
            ["errorcode"] = "AccessDenied"
        }));
    }

    [Fact]
    public void Broken_rules_are_collected_as_load_errors_not_thrown()
    {
        var engine = EngineWith(
            ("good", ConsoleLoginNoMfa),
            ("bad", "title: No Detection Here\nlogsource:\n  product: aws\n"));

        Assert.Equal(1, engine.RuleCount);
        var error = Assert.Single(engine.LoadErrors);
        Assert.Contains("bad.yml", error);
    }

    [Fact]
    public void Condition_referencing_unknown_selection_is_rejected()
    {
        const string yaml = """
            title: Broken Condition
            detection:
              selection:
                eventName: ConsoleLogin
              condition: selection and ghost
            """;

        var engine = EngineWith(("broken", yaml));

        Assert.Equal(0, engine.RuleCount);
        Assert.Single(engine.LoadErrors);
    }

    [Fact]
    public void Shipped_cloudtrail_pack_loads_clean()
    {
        // Walk up from the test bin to the repo root that holds rules/.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "rules")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        var engine = SigmaEngine.LoadFromDirectory(Path.Combine(dir.FullName, "rules"));

        Assert.Empty(engine.LoadErrors);
        Assert.True(engine.RuleCount >= 8, $"Expected >= 8 shipped rules, got {engine.RuleCount}.");
    }

    [Fact]
    public void EvaluateBatch_counts_hits_per_rule()
    {
        var engine = EngineWith(("rule1", ConsoleLoginNoMfa));

        var events = new[]
        {
            new Dictionary<string, string> { ["eventname"] = "ConsoleLogin" },
            new Dictionary<string, string> { ["eventname"] = "ConsoleLogin" },
            new Dictionary<string, string> { ["eventname"] = "GetObject" }
        };

        var (rule, hits) = Assert.Single(engine.EvaluateBatch(events));
        Assert.Equal("AWS Console Login Without MFA", rule.Title);
        Assert.Equal(2, hits);
    }
}
