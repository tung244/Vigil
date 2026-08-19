using Vigil.Core.Domain;
using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

public class ReportValidatorTests
{
    [Theory]
    [InlineData(0.0, Severity.Low)]
    [InlineData(2.49, Severity.Low)]
    [InlineData(2.5, Severity.Medium)]
    [InlineData(4.9, Severity.Medium)]
    [InlineData(5.0, Severity.High)]
    [InlineData(7.4, Severity.High)]
    [InlineData(7.5, Severity.Critical)]
    [InlineData(10.0, Severity.Critical)]
    public void Severity_bands_map_risk_scores(double riskScore, Severity expected)
    {
        Assert.Equal(expected, ReportValidator.SeverityForScore(riskScore));
    }

    [Fact]
    public void Fully_valid_report_has_no_violations()
    {
        Assert.Empty(ReportValidator.Validate(ValidReport()));
    }

    [Theory]
    // score 8.0 is in the critical band (7.5-10); every other severity must be rejected
    [InlineData(Severity.Low)]
    [InlineData(Severity.Medium)]
    [InlineData(Severity.High)]
    public void Severity_must_match_the_risk_score_band(Severity wrongSeverity)
    {
        var mismatched = Copy(ValidReport(), severity: wrongSeverity, riskScore: 8.0);

        var violations = ReportValidator.Validate(mismatched);

        Assert.Contains(violations, v => v.Contains("does not match risk_score"));
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(10.5)]
    public void Risk_score_outside_0_10_is_rejected(double riskScore)
    {
        var violations = ReportValidator.Validate(Copy(ValidReport(), riskScore: riskScore));

        Assert.Contains(violations, v => v.Contains("0-10"));
    }

    [Theory]
    [InlineData("T1566", true)]
    [InlineData("T1566.001", true)]
    [InlineData("TA0001", false)]
    [InlineData("T123", false)]
    [InlineData("T12345", false)]
    [InlineData("t1566", false)]
    [InlineData("T1566.1", false)]
    [InlineData("T1566.001 extra", false)]
    public void Mitre_technique_ids_must_match_the_attack_format(string technique, bool valid)
    {
        var violations = ReportValidator.Validate(Copy(ValidReport(), mitreTechniques: [technique]));

        Assert.Equal(!valid, violations.Any(v => v.Contains("not a valid ATT&CK technique id")));
    }

    [Fact]
    public void Empty_mitre_techniques_are_rejected()
    {
        var violations = ReportValidator.Validate(Copy(ValidReport(), mitreTechniques: []));

        Assert.Contains(violations, v => v.Contains("mitre_techniques must not be empty"));
    }

    [Fact]
    public void Empty_evidence_trail_is_rejected()
    {
        var violations = ReportValidator.Validate(Copy(ValidReport(), evidenceTrail: []));

        Assert.Contains(violations, v => v.Contains("evidence_trail must not be empty"));
    }

    private static SynthesisResult ValidReport() => new()
    {
        RiskScore = 6.5,
        Severity = Severity.High,
        SummaryMarkdown = "# Report\nFindings.",
        MitreTechniques = ["T1566.002"],
        RecommendedActions = ["Block the sender domain"],
        EvidenceTrail = [new EvidenceItem("SPF failed for the sender domain", "rule:spf_fail")]
    };

    private static SynthesisResult Copy(
        SynthesisResult r,
        double? riskScore = null,
        Severity? severity = null,
        IReadOnlyList<string>? mitreTechniques = null,
        IReadOnlyList<EvidenceItem>? evidenceTrail = null) => new()
    {
        RiskScore = riskScore ?? r.RiskScore,
        Severity = severity ?? r.Severity,
        SummaryMarkdown = r.SummaryMarkdown,
        MitreTechniques = mitreTechniques ?? r.MitreTechniques,
        RecommendedActions = r.RecommendedActions,
        EvidenceTrail = evidenceTrail ?? r.EvidenceTrail
    };
}
