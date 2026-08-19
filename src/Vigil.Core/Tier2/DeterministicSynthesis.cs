using System.Text;
using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>
/// Rule-based fallback for the Synthesis stage when no LLM is configured
/// (Llm:ApiKey empty). Unlike the old system, where synthesis without Gemini
/// returned a bare error string, Vigil still produces a usable report built
/// purely from the structured evidence bundle — important for demo resilience
/// and for non-email jobs, which otherwise could never complete without an LLM
/// key. The report is marked "[generated without LLM]" and passes
/// <see cref="ReportValidator"/> by construction (severity is derived from the
/// score via <see cref="ReportValidator.SeverityForScore"/>).
/// </summary>
public static class DeterministicSynthesis
{
    public const string FallbackMarker = "[generated without LLM]";

    public static SynthesisResult Build(SynthesisEvidence evidence)
    {
        var riskScore = ComputeRiskScore(evidence);
        var severity = ReportValidator.SeverityForScore(riskScore);

        return new SynthesisResult
        {
            RiskScore = riskScore,
            Severity = severity,
            SummaryMarkdown = BuildSummary(evidence, riskScore, severity),
            MitreTechniques = MapMitreTechniques(evidence),
            RecommendedActions = BuildActions(evidence),
            EvidenceTrail = BuildEvidenceTrail(evidence, riskScore)
        };
    }

    /// <summary>
    /// Explainable 0–10 score: Tier 1 rule score contributes up to 4 points,
    /// the ML phishing probability up to 3, the highest threat intel score up
    /// to 2, and a phishing verdict from the email analyst adds 1.
    /// </summary>
    internal static double ComputeRiskScore(SynthesisEvidence evidence)
    {
        var score = evidence.Tier1RuleScore / 100.0 * 4.0
            + (evidence.MlScore ?? 0.0) * 3.0
            + evidence.Iocs.SelectMany(i => i.Intel)
                .Select(i => i.MaliciousScore)
                .DefaultIfEmpty(0.0)
                .Max() * 2.0
            + (evidence.EmailAnalysis?.Status == EmailVerdict.Phishing ? 1.0 : 0.0);
        return Math.Round(Math.Clamp(score, 0.0, 10.0), 1);
    }

    internal static List<string> MapMitreTechniques(SynthesisEvidence evidence)
    {
        var techniques = new List<string>();
        bool HasRule(string prefix) =>
            evidence.MatchedRules.Any(r => r.StartsWith(prefix, StringComparison.Ordinal));

        if (evidence.ArtifactType == nameof(ArtifactType.Eml))
        {
            if (evidence.Iocs.Any(i => i.Type == nameof(IocType.Url)))
            {
                techniques.Add("T1566.002"); // Spearphishing Link
            }

            // Keyword rules and auth failures carry no ':' suffix family prefix.
            if (evidence.MatchedRules.Any(r => !r.Contains(':', StringComparison.Ordinal))
                || HasRule("suspicious_domain") || HasRule("lookalike_domain"))
            {
                techniques.Add("T1566"); // Phishing
            }

            if (techniques.Count == 0)
            {
                techniques.Add("T1566");
            }
        }
        else
        {
            if (HasRule("recon_burst") || HasRule("access_denied"))
            {
                techniques.Add("T1087"); // Account Discovery
            }

            if (HasRule("high_risk_api:DeleteTrail") || HasRule("high_risk_api:StopLogging")
                || HasRule("high_risk_api:UpdateTrail") || HasRule("high_risk_api:PutEventSelectors"))
            {
                techniques.Add("T1562.008"); // Impair Defenses: Disable or Modify Cloud Logs
            }
            else if (HasRule("high_risk_api"))
            {
                techniques.Add("T1098"); // Account Manipulation
            }

            if (HasRule("sensitive_event_unseen_ip") || HasRule("user_event_count_anomaly")
                || HasRule("ip_event_count_anomaly") || HasRule("user_event_frequency_spike")
                || HasRule("ip_event_frequency_spike"))
            {
                techniques.Add("T1078"); // Valid Accounts
            }

            if (techniques.Count == 0)
            {
                techniques.Add("T1078");
            }
        }

        return techniques.Distinct().ToList();
    }

    private static string BuildSummary(SynthesisEvidence evidence, double riskScore, Severity severity)
    {
        var sb = new StringBuilder();
        sb.AppendLine(FallbackMarker);
        sb.AppendLine();
        sb.AppendLine("## Incident summary (rule-based, no LLM synthesis)");
        sb.AppendLine();
        sb.AppendLine($"- Artifact: `{evidence.FileName}` ({evidence.ArtifactType})");
        sb.AppendLine($"- Tier 1 verdict: **{evidence.Tier1Verdict}** (rule score {evidence.Tier1RuleScore}/100"
            + (evidence.MlScore is { } ml ? $", ML phishing probability {ml:F3}" : string.Empty) + ")");
        sb.AppendLine(evidence.MatchedRules.Count > 0
            ? $"- Matched rules: {string.Join(", ", evidence.MatchedRules.Select(r => $"`{r}`"))}"
            : "- Matched rules: none");

        var intelCount = evidence.Iocs.Sum(i => i.Intel.Count);
        sb.AppendLine($"- IOCs: {evidence.Iocs.Count} ({intelCount} threat intel lookups)");
        foreach (var ioc in evidence.Iocs)
        {
            var intel = ioc.Intel.Count == 0
                ? "not enriched"
                : string.Join("; ", ioc.Intel.Select(i =>
                    $"{i.Source} score {i.MaliciousScore:F2} ({(i.FromLiveApi ? "live API" : "heuristic analysis only")})"));
            sb.AppendLine($"  - `{ioc.Type}` `{ioc.Value}` ({ioc.ExtractedBy}) — {intel}");
        }

        if (evidence.EmailAnalysis is { } analysis)
        {
            sb.AppendLine($"- Email analyst: {analysis.Status} (confidence {analysis.Confidence:F2}) — {analysis.Summary}");
        }

        if (evidence.CloudtrailEvents.Count > 0)
        {
            sb.AppendLine($"- Correlated CloudTrail events: {evidence.CloudtrailEvents.Count} (source IP matches an IOC)");
        }

        sb.AppendLine();
        sb.AppendLine($"**Risk score: {riskScore:F1}/10 — severity: {severity}**");
        sb.AppendLine();
        sb.AppendLine("_LLM synthesis unavailable (no Llm:ApiKey configured); this report was "
            + "generated from structured evidence only. Re-run with an LLM key for a full analyst narrative._");
        return sb.ToString();
    }

    private static List<string> BuildActions(SynthesisEvidence evidence)
    {
        var actions = new List<string>();
        if (evidence.ArtifactType == nameof(ArtifactType.Eml))
        {
            actions.Add("Quarantine the email and block the sender address/domain at the mail gateway.");
            actions.Add("Add the extracted URLs/IPs to the proxy and DNS blocklists.");
            actions.Add("Notify recipients and reset credentials of anyone who may have interacted with the email.");
        }
        else
        {
            actions.Add("Disable or rotate credentials of the flagged user accounts pending review.");
            actions.Add("Block the flagged source IPs at the network perimeter.");
            actions.Add("Review the flagged high-risk API calls with the account owner.");
        }

        if (evidence.CloudtrailEvents.Count > 0)
        {
            actions.Add("Investigate the correlated CloudTrail activity from the IOC source IPs.");
        }

        return actions;
    }

    private static List<EvidenceItem> BuildEvidenceTrail(SynthesisEvidence evidence, double riskScore)
    {
        var trail = new List<EvidenceItem>
        {
            new($"Tier 1 verdict {evidence.Tier1Verdict} with rule score {evidence.Tier1RuleScore}/100"
                + (evidence.MatchedRules.Count > 0
                    ? $"; matched rules: {string.Join(", ", evidence.MatchedRules)}"
                    : string.Empty),
                "tier1.rule_check_results")
        };

        if (evidence.MlScore is { } ml)
        {
            trail.Add(new EvidenceItem($"ML phishing probability {ml:F3}.", "ml_score"));
        }

        foreach (var ioc in evidence.Iocs)
        {
            foreach (var intel in ioc.Intel)
            {
                trail.Add(new EvidenceItem(
                    $"{ioc.Type} {ioc.Value} scored {intel.MaliciousScore:F2} by {intel.Source} "
                    + (intel.FromLiveApi ? "(live API)." : "(heuristic analysis only)."),
                    $"intel:{intel.Source}"));
            }
        }

        if (evidence.EmailAnalysis is { } analysis)
        {
            trail.Add(new EvidenceItem(
                $"Email analyst verdict {analysis.Status} (confidence {analysis.Confidence:F2}): {analysis.Summary}",
                "email_analysis"));
        }

        foreach (var evt in evidence.CloudtrailEvents)
        {
            trail.Add(new EvidenceItem(
                $"CloudTrail event {evt.EventName} from {evt.SourceIp ?? "unknown IP"} "
                + $"by {evt.UserIdentity ?? "unknown identity"} at {evt.EventTime:O}.",
                "cloudtrail"));
        }

        trail.Add(new EvidenceItem(
            $"Deterministic risk score {riskScore:F1}/10 (rule score, ML score, intel scores, email verdict).",
            "deterministic_scoring"));

        return trail;
    }
}
