using Vigil.Core.Domain;
using Vigil.Core.Pipeline;

namespace Vigil.UnitTests.Pipeline;

public class Tier2StateMachineTests
{
    [Fact]
    public void Eml_jobs_start_at_email_analysis_and_walk_all_states()
    {
        Assert.Equal(
            [Tier2State.EmailAnalysis, Tier2State.ThreatIntelEnrichment, Tier2State.SynthesisPending, Tier2State.Synthesis],
            Tier2StateMachine.PathFor(ArtifactType.Eml));
        Assert.Equal(Tier2State.EmailAnalysis, Tier2StateMachine.InitialState(ArtifactType.Eml));
    }

    [Theory]
    [InlineData(ArtifactType.Csv)]
    [InlineData(ArtifactType.Json)]
    public void Non_email_jobs_skip_email_analysis_and_go_straight_to_threat_intel(ArtifactType type)
    {
        Assert.Equal(
            [Tier2State.ThreatIntelEnrichment, Tier2State.SynthesisPending, Tier2State.Synthesis],
            Tier2StateMachine.PathFor(type));
        Assert.Equal(Tier2State.ThreatIntelEnrichment, Tier2StateMachine.InitialState(type));
    }

    [Fact]
    public void Next_advances_until_the_terminal_state()
    {
        Assert.Equal(Tier2State.ThreatIntelEnrichment, Tier2StateMachine.Next(Tier2State.EmailAnalysis));
        Assert.Equal(Tier2State.SynthesisPending, Tier2StateMachine.Next(Tier2State.ThreatIntelEnrichment));
        Assert.Equal(Tier2State.Synthesis, Tier2StateMachine.Next(Tier2State.SynthesisPending));
        Assert.Throws<InvalidOperationException>(() => Tier2StateMachine.Next(Tier2State.Synthesis));
    }

    [Theory]
    [InlineData(Tier2State.EmailAnalysis, "tier2.email_analysis")]
    [InlineData(Tier2State.ThreatIntelEnrichment, "tier2.threat_intel")]
    [InlineData(Tier2State.SynthesisPending, "tier2.synthesis_pending")]
    [InlineData(Tier2State.Synthesis, "tier2.synthesis")]
    public void Step_names_match_the_pipeline_progress_convention(Tier2State state, string expected)
    {
        Assert.Equal(expected, Tier2StateMachine.StepName(state));
    }
}
