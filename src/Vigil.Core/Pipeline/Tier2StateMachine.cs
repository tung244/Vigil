using Vigil.Core.Domain;

namespace Vigil.Core.Pipeline;

/// <summary>States of the deterministic Tier 2 agent pipeline.</summary>
public enum Tier2State
{
    /// <summary>LLM email analyst: IOC extraction + phishing verdict (.eml only).</summary>
    EmailAnalysis,

    /// <summary>Enrich every job IOC via the threat intel service (tool calls only, no LLM).</summary>
    ThreatIntelEnrichment,

    /// <summary>Tier 2 finished; waiting for synthesis/report (Step 8).</summary>
    SynthesisPending
}

/// <summary>
/// Deterministic Tier 2 routing — the core architectural difference from the
/// old LangGraph rebuild, which used an LLM supervisor to route between
/// agents. Here the path is fixed in C#: the LLM only does in-step tool
/// calling, never routing. Non-email artifacts skip the email analyst and go
/// straight to threat intel with the IOCs Tier 1 rules already extracted.
/// </summary>
public static class Tier2StateMachine
{
    /// <summary>The full ordered path for an artifact type.</summary>
    public static IReadOnlyList<Tier2State> PathFor(ArtifactType artifactType) =>
        artifactType == ArtifactType.Eml
            ? [Tier2State.EmailAnalysis, Tier2State.ThreatIntelEnrichment, Tier2State.SynthesisPending]
            : [Tier2State.ThreatIntelEnrichment, Tier2State.SynthesisPending];

    /// <summary>Where a job of this artifact type enters Tier 2.</summary>
    public static Tier2State InitialState(ArtifactType artifactType) => PathFor(artifactType)[0];

    /// <summary>The successor state. <see cref="Tier2State.SynthesisPending"/> is terminal.</summary>
    public static Tier2State Next(Tier2State current) => current switch
    {
        Tier2State.EmailAnalysis => Tier2State.ThreatIntelEnrichment,
        Tier2State.ThreatIntelEnrichment => Tier2State.SynthesisPending,
        _ => throw new InvalidOperationException($"{current} is a terminal Tier 2 state.")
    };

    /// <summary>The value written to <see cref="AnalysisJob.CurrentStep"/> while a state runs.</summary>
    public static string StepName(Tier2State state) => state switch
    {
        Tier2State.EmailAnalysis => "tier2.email_analysis",
        Tier2State.ThreatIntelEnrichment => "tier2.threat_intel",
        Tier2State.SynthesisPending => "tier2.synthesis_pending",
        _ => throw new ArgumentOutOfRangeException(nameof(state), state, null)
    };
}
