using System.Text.RegularExpressions;
using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>
/// Deterministic post-synthesis validator — the port of the old
/// <c>report_validator.py</c> idea to the structured JSON report. Prompt
/// engineering cannot guarantee the contract, so every synthesized report
/// (LLM or fallback) is checked here before persistence. A report with
/// violations is rejected; the stage retries once with the violation list and
/// fails the job if the retry still violates.
/// </summary>
public static partial class ReportValidator
{
    /// <summary>
    /// Severity bands (documented in the synthesis prompt so the LLM can
    /// comply up front):
    /// 0.0–2.49 → Low, 2.5–4.9 → Medium, 5.0–7.4 → High, 7.5–10.0 → Critical.
    /// </summary>
    public static Severity SeverityForScore(double riskScore) => riskScore switch
    {
        < 2.5 => Severity.Low,
        < 5.0 => Severity.Medium,
        < 7.5 => Severity.High,
        _ => Severity.Critical
    };

    /// <summary>Returns all contract violations; an empty list means the report is valid.</summary>
    public static IReadOnlyList<string> Validate(SynthesisResult report)
    {
        var violations = new List<string>();

        if (double.IsNaN(report.RiskScore) || double.IsInfinity(report.RiskScore)
            || report.RiskScore is < 0 or > 10)
        {
            violations.Add($"risk_score {report.RiskScore} is outside the 0-10 range.");
        }
        else if (SeverityForScore(report.RiskScore) != report.Severity)
        {
            violations.Add(
                $"severity '{report.Severity}' does not match risk_score {report.RiskScore} " +
                $"(expected '{SeverityForScore(report.RiskScore)}'; bands: 0-2.49 low, 2.5-4.9 medium, " +
                "5-7.4 high, 7.5-10 critical).");
        }

        if (report.MitreTechniques.Count == 0)
        {
            violations.Add("mitre_techniques must not be empty — map the evidence to at least one ATT&CK technique.");
        }

        foreach (var technique in report.MitreTechniques.Where(t => !MitreTechniqueRegex().IsMatch(t)))
        {
            violations.Add(
                $"mitre technique '{technique}' is not a valid ATT&CK technique id (expected Txxxx or Txxxx.yyy).");
        }

        if (report.EvidenceTrail.Count == 0)
        {
            violations.Add("evidence_trail must not be empty — every claim must link to its evidence source.");
        }

        return violations;
    }

    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")]
    private static partial Regex MitreTechniqueRegex();
}
