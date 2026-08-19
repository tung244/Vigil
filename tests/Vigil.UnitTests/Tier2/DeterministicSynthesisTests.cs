using Vigil.Core.Domain;
using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

public class DeterministicSynthesisTests
{
    [Fact]
    public void Fallback_report_passes_the_validator_and_is_marked_as_non_llm()
    {
        var report = DeterministicSynthesis.Build(EmailEvidence());

        Assert.Empty(ReportValidator.Validate(report));
        Assert.StartsWith(DeterministicSynthesis.FallbackMarker, report.SummaryMarkdown);
        Assert.Equal(ReportValidator.SeverityForScore(report.RiskScore), report.Severity);
        Assert.NotEmpty(report.EvidenceTrail);
        Assert.NotEmpty(report.RecommendedActions);
    }

    [Fact]
    public void Email_with_urls_maps_to_spearphishing_link_technique()
    {
        var report = DeterministicSynthesis.Build(EmailEvidence());

        Assert.Contains("T1566.002", report.MitreTechniques);
        Assert.Contains("T1566", report.MitreTechniques);
    }

    [Fact]
    public void Csv_log_rules_map_to_discovery_and_valid_accounts_techniques()
    {
        var evidence = new SynthesisEvidence
        {
            FileName = "authlog.csv",
            ArtifactType = nameof(ArtifactType.Csv),
            Tier1Verdict = "Suspicious",
            Tier1RuleScore = 60,
            MatchedRules = ["recon_burst:alice:5", "high_risk_api:StopLogging", "ip_event_count_anomaly:10.0.0.9:z=3.5"],
            Iocs = [new IocEvidence("Ip", "10.0.0.9", "Rule", [new IntelEvidence("AbuseIpDb", 0.9, true)])],
            CloudtrailEvents = []
        };

        var report = DeterministicSynthesis.Build(evidence);

        Assert.Contains("T1087", report.MitreTechniques);
        Assert.Contains("T1562.008", report.MitreTechniques);
        Assert.Contains("T1078", report.MitreTechniques);
        Assert.Empty(ReportValidator.Validate(report));
    }

    [Fact]
    public void Risk_score_combines_rule_ml_intel_and_verdict_signals()
    {
        // rule score 100/100 → 4.0; ml 0.5 → 1.5; intel max 1.0 → 2.0; phishing verdict → 1.0; total 8.5
        var score = DeterministicSynthesis.ComputeRiskScore(EmailEvidence());

        Assert.Equal(8.5, score);
    }

    [Fact]
    public void Evidence_trail_links_every_signal_to_its_source()
    {
        var report = DeterministicSynthesis.Build(EmailEvidence());

        Assert.Contains(report.EvidenceTrail, e => e.Source == "tier1.rule_check_results");
        Assert.Contains(report.EvidenceTrail, e => e.Source == "ml_score");
        Assert.Contains(report.EvidenceTrail, e => e.Source == "intel:VirusTotal");
        Assert.Contains(report.EvidenceTrail, e => e.Source == "email_analysis");
        // Heuristic intel must be disclosed as such (evidence discipline port).
        Assert.Contains(report.EvidenceTrail, e => e.Claim.Contains("heuristic analysis only"));
    }

    private static SynthesisEvidence EmailEvidence() => new()
    {
        FileName = "mail.eml",
        ArtifactType = nameof(ArtifactType.Eml),
        Tier1Verdict = "Suspicious",
        Tier1RuleScore = 100,
        MatchedRules = ["spf_fail", "urgent_action_required"],
        MlScore = 0.5,
        Iocs =
        [
            new IocEvidence("Url", "https://evil.example/login", "Rule",
                [new IntelEvidence("VirusTotal", 1.0, false)])
        ],
        EmailAnalysis = new EmailAnalysisResult
        {
            Status = EmailVerdict.Phishing,
            Confidence = 0.9,
            Summary = "Phishing lure."
        },
        CloudtrailEvents = []
    };
}
