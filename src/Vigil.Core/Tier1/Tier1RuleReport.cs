using Vigil.Core.Domain;

namespace Vigil.Core.Tier1;

/// <summary>Outcome of a single named check, kept for auditability.</summary>
/// <param name="Name">Stable check identifier, e.g. "auth_spf", "user_frequency".</param>
/// <param name="Result">Machine-readable outcome: "pass", "fail", "flag", "not_present", "info".</param>
/// <param name="Detail">Human-readable explanation, e.g. "spf=fail (sender domain evil.example)".</param>
public sealed record RuleCheck(string Name, string Result, string Detail);

/// <summary>
/// Serializable outcome of the Tier 1 rule checks for one artifact.
/// Stored as-is (camelCase JSON) in <c>tier1_results.rule_check_results</c> (jsonb).
/// </summary>
public sealed class Tier1RuleReport
{
    /// <summary>Artifact kind the rules ran against ("Eml", "Csv", "Json").</summary>
    public required string ArtifactType { get; init; }

    /// <summary>Explainable 0–100 score built from the matched rules and extractions.</summary>
    public int RiskScore { get; set; }

    /// <summary>Security-first: a single matched rule escalates to Suspicious.</summary>
    public Tier1Verdict Verdict { get; set; } = Tier1Verdict.Benign;

    /// <summary>Stable rule identifiers that fired, e.g. "spf_fail", "recon_burst:4".</summary>
    public List<string> MatchedRules { get; } = [];

    /// <summary>Every check that ran, whether it flagged or not.</summary>
    public List<RuleCheck> Checks { get; } = [];

    /// <summary>Artifacts extracted while checking (sender, urls, ips, stats, ...).</summary>
    public Dictionary<string, object?> Extracted { get; } = [];

    /// <summary>Applies the verdict policy: any matched rule means Suspicious.</summary>
    public void ApplyVerdict() =>
        Verdict = MatchedRules.Count > 0 ? Tier1Verdict.Suspicious : Tier1Verdict.Benign;
}
