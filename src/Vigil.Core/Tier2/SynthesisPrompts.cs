namespace Vigil.Core.Tier2;

/// <summary>
/// Prompt contract for the Synthesis stage. Condensed port of the old
/// <c>synthesis.py</c> evidence discipline: observed-vs-assessed separation,
/// threat intel transparency (heuristic lookups are never shown as API
/// verdicts), IOC preservation and current MITRE ATT&amp;CK IDs only. The old
/// free-form markdown report is replaced by a strict JSON contract so the
/// result can be persisted and validated field by field
/// (<see cref="SynthesisResponseParser"/>, <see cref="ReportValidator"/>).
/// </summary>
public static class SynthesisPrompts
{
    public const string SystemPrompt = """
        You are the Synthesis agent of Vigil, a banking security threat detection system.
        You receive the complete evidence bundle of one analysis job (Tier 1 rule
        verdict, ML phishing score, extracted IOCs, threat intel lookups, optional
        email analysis, correlated CloudTrail events) and produce the final
        incident report.

        EVIDENCE DISCIPLINE — MANDATORY RULES:
        1. Observed vs assessed: every claim in summary_markdown and evidence_trail
           must trace to a specific field of the evidence bundle. Mark inferences
           with "likely" / "suggests" / "consistent with"; never present an
           assessment as an observed fact.
        2. Threat intel transparency: intel entries with fromLiveApi=false are
           heuristic-only — write "heuristic analysis only" for them and NEVER
           fabricate reputation numbers. IOCs are "contextually suspicious", not
           "malicious", unless live API data says so.
        3. IOC preservation: show full IOC values (IPs, domains, URLs, addresses).
           They are indicators, not PII — never redact them.
        4. Datasource fidelity: email evidence cannot prove a link was clicked or
           a payload executed; log evidence cannot prove email content. Say
           "no evidence of X in the provided data" instead of "X was not confirmed".
        5. MITRE ATT&CK: use ONLY current technique IDs (Txxxx or Txxxx.yyy).
           Deprecated IDs to avoid: T1192 → T1566.002, T1193 → T1566.001,
           T1194 → T1566.003, T1064 → T1059. Match techniques to what the evidence
           actually shows, not to what you infer the attacker intended.

        Respond with ONLY a JSON object matching this contract — no markdown
        fences, no commentary:

        {
          "risk_score": <number 0.0-10.0>,
          "severity": "low" | "medium" | "high" | "critical",
          "summary_markdown": "<markdown report: executive summary, key findings, IOC table>",
          "mitre_techniques": ["T1566.001", ...],
          "recommended_actions": ["<concrete action>", ...],
          "evidence_trail": [{"claim": "<one claim>", "source": "<where the evidence came from>"}, ...]
        }

        Contract rules (a validator enforces them; violations reject the report):
        - severity MUST match risk_score: 0-2.49 → low, 2.5-4.9 → medium,
          5-7.4 → high, 7.5-10 → critical.
        - mitre_techniques must not be empty; every entry matches T\d{4}(\.\d{3})?.
        - evidence_trail must not be empty. Each source names the concrete origin,
          e.g. "rule:spf_fail", "ml_score", "ioc:url=https://evil.example",
          "intel:VirusTotal", "email_analysis", "cloudtrail".
        - recommended_actions: 2-6 concrete, actionable steps based on observed
          evidence only.
        """;

    /// <summary>Sent after a response that failed parsing; exactly one retry is attempted.</summary>
    public const string FormatRetryInstruction =
        "Your previous response was not valid JSON matching the required schema. " +
        "Respond with ONLY the JSON object — no markdown fences, no commentary.";

    /// <summary>Sent after a response that parsed but violated the report contract.</summary>
    public static string BuildValidationRetryInstruction(IReadOnlyList<string> violations) => $"""
        Your previous response violated the report contract:
        {string.Join("\n", violations.Select(v => "- " + v))}

        Respond with ONLY the corrected JSON object — no markdown fences, no commentary.
        """;

    /// <summary>Builds the user message: the whole evidence bundle as JSON.</summary>
    public static string BuildUserPrompt(string evidenceJson) => BuildUserPrompt(evidenceJson, []);

    /// <summary>
    /// Builds the user message: the evidence bundle as JSON plus, when present,
    /// a RAG section with similar past incidents
    /// (<see cref="BuildSimilarIncidentsSection"/>).
    /// </summary>
    public static string BuildUserPrompt(string evidenceJson, IReadOnlyList<SimilarIncidentEvidence> similarIncidents)
    {
        var similarSection = BuildSimilarIncidentsSection(similarIncidents);
        return $"""
            Synthesize the final incident report for this job.

            Evidence bundle (all fields are observed data; reason only about these):
            {evidenceJson}
            {(similarSection.Length == 0 ? string.Empty : "\n" + similarSection + "\n")}
            Provide the report as the JSON object described in the system instructions.
            """;
    }

    /// <summary>
    /// Renders similar past incidents (pgvector RAG) as a short markdown
    /// section for the synthesis prompt: risk score, severity, top matched
    /// rules and the (already truncated) summary excerpt per incident.
    /// Returns an empty string when there is nothing to show.
    /// </summary>
    public static string BuildSimilarIncidentsSection(IReadOnlyList<SimilarIncidentEvidence> similarIncidents)
    {
        if (similarIncidents.Count == 0)
        {
            return string.Empty;
        }

        var builder = new System.Text.StringBuilder();
        builder.AppendLine("""
            Similar past incidents (retrieved by embedding similarity — background
            context only; never present their conclusions as observed facts of THIS job):
            """);
        foreach (var incident in similarIncidents)
        {
            var rules = incident.MatchedRules.Count == 0
                ? "none"
                : string.Join(", ", incident.MatchedRules.Take(5));
            builder.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"""
                - risk {incident.RiskScore:F1} ({incident.Severity}), similarity {incident.Similarity:F2}, rules: {rules}
                  summary: {incident.SummaryExcerpt}
                """);
        }

        return builder.ToString().TrimEnd();
    }
}
