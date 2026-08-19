using Vigil.Core.Domain;
using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

public class SynthesisResponseParserTests
{
    private const string ValidJson = """
        {
          "risk_score": 6.5,
          "severity": "high",
          "summary_markdown": "# Report\nFindings.",
          "mitre_techniques": ["T1566.001"],
          "recommended_actions": ["Block the sender domain"],
          "evidence_trail": [{"claim": "SPF failed", "source": "rule:spf_fail"}]
        }
        """;

    [Fact]
    public void Valid_bare_json_parses_all_fields()
    {
        Assert.True(SynthesisResponseParser.TryParse(ValidJson, out var result));

        Assert.Equal(6.5, result!.RiskScore);
        Assert.Equal(Severity.High, result.Severity);
        Assert.Equal("# Report\nFindings.", result.SummaryMarkdown);
        Assert.Equal(["T1566.001"], result.MitreTechniques);
        Assert.Equal(["Block the sender domain"], result.RecommendedActions);
        Assert.Equal([new EvidenceItem("SPF failed", "rule:spf_fail")], result.EvidenceTrail);
    }

    [Fact]
    public void Json_wrapped_in_a_markdown_fence_is_accepted()
    {
        var fenced = $"Here is the report:\n```json\n{ValidJson}\n```";

        Assert.True(SynthesisResponseParser.TryParse(fenced, out var result));
        Assert.Equal(6.5, result!.RiskScore);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("this is not json at all")]
    [InlineData("{\"risk_score\": \"not-a-number\"}")]
    public void Non_json_or_wrong_shapes_are_rejected(string? raw)
    {
        Assert.False(SynthesisResponseParser.TryParse(raw, out var result));
        Assert.Null(result);
    }

    [Fact]
    public void Missing_risk_score_is_rejected()
    {
        const string raw = """
            {"severity": "high", "summary_markdown": "x", "mitre_techniques": ["T1566"],
             "recommended_actions": [], "evidence_trail": [{"claim": "c", "source": "s"}]}
            """;

        Assert.False(SynthesisResponseParser.TryParse(raw, out _));
    }

    [Fact]
    public void Unknown_severity_is_rejected()
    {
        var raw = ValidJson.Replace("\"severity\": \"high\"", "\"severity\": \"apocalyptic\"");

        Assert.False(SynthesisResponseParser.TryParse(raw, out _));
    }

    [Fact]
    public void Blank_summary_is_rejected()
    {
        var raw = ValidJson.Replace("\"# Report\\nFindings.\"", "\"  \"");

        Assert.False(SynthesisResponseParser.TryParse(raw, out _));
    }

    [Fact]
    public void Evidence_items_with_blank_claim_or_source_are_dropped()
    {
        const string raw = """
            {"risk_score": 1.0, "severity": "low", "summary_markdown": "ok",
             "mitre_techniques": ["T1566"], "recommended_actions": [],
             "evidence_trail": [{"claim": "c", "source": "s"}, {"claim": "", "source": "s"}, {"claim": "c2"}]}
            """;

        Assert.True(SynthesisResponseParser.TryParse(raw, out var result));
        Assert.Equal([new EvidenceItem("c", "s")], result!.EvidenceTrail);
    }
}
