using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

/// <summary>
/// The RAG prompt section: similar past incidents rendered for the synthesis
/// prompt (<see cref="SynthesisPrompts.BuildSimilarIncidentsSection"/>) and
/// appended to the user prompt only when present.
/// </summary>
public class SynthesisPromptsTests
{
    private static readonly SimilarIncidentEvidence Incident = new(
        Guid.Parse("11111111-1111-1111-1111-111111111111"),
        RiskScore: 8.4,
        Severity: "Critical",
        MatchedRules: ["spf_fail", "lookalike_domain"],
        SummaryExcerpt: "Credential-harvesting lure impersonating a banking portal.",
        Similarity: 0.8734);

    [Fact]
    public void Similar_incidents_section_is_empty_when_nothing_was_retrieved()
    {
        Assert.Equal(string.Empty, SynthesisPrompts.BuildSimilarIncidentsSection([]));
    }

    [Fact]
    public void Similar_incidents_section_lists_risk_severity_rules_and_summary()
    {
        var section = SynthesisPrompts.BuildSimilarIncidentsSection([Incident]);

        Assert.Contains("risk 8.4 (Critical)", section);
        Assert.Contains("similarity 0.87", section);
        Assert.Contains("spf_fail", section);
        Assert.Contains("lookalike_domain", section);
        Assert.Contains("Credential-harvesting lure", section);
        // The section must carry the context-only guard for the LLM.
        Assert.Contains("never present their conclusions as observed facts", section);
    }

    [Fact]
    public void Similar_incidents_section_caps_the_rule_list_at_five()
    {
        var manyRules = Incident with
        {
            MatchedRules = ["r1", "r2", "r3", "r4", "r5", "r6", "r7"]
        };

        var section = SynthesisPrompts.BuildSimilarIncidentsSection([manyRules]);

        Assert.Contains("r5", section);
        Assert.DoesNotContain("r6", section);
    }

    [Fact]
    public void User_prompt_omits_the_section_when_there_are_no_similar_incidents()
    {
        var prompt = SynthesisPrompts.BuildUserPrompt("{ \"fileName\": \"a.eml\" }", []);

        Assert.Contains("{ \"fileName\": \"a.eml\" }", prompt);
        Assert.DoesNotContain("Similar past incidents", prompt);
    }

    [Fact]
    public void User_prompt_appends_the_section_after_the_evidence_json()
    {
        var prompt = SynthesisPrompts.BuildUserPrompt("{ \"fileName\": \"a.eml\" }", [Incident]);

        var evidenceIndex = prompt.IndexOf("{ \"fileName\": \"a.eml\" }", StringComparison.Ordinal);
        var sectionIndex = prompt.IndexOf("Similar past incidents", StringComparison.Ordinal);
        Assert.True(sectionIndex > evidenceIndex);
        Assert.Contains("Credential-harvesting lure", prompt);
    }

    [Fact]
    public void SynthesisEvidence_defaults_to_no_similar_incidents()
    {
        var evidence = new SynthesisEvidence
        {
            FileName = "a.eml",
            ArtifactType = "Eml",
            Tier1Verdict = "Suspicious",
            Tier1RuleScore = 10,
            MatchedRules = [],
            Iocs = [],
            CloudtrailEvents = []
        };

        Assert.Empty(evidence.SimilarIncidents);
    }
}
