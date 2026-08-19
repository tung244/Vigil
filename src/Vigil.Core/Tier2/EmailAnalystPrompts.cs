namespace Vigil.Core.Tier2;

/// <summary>
/// Prompt contract for the Email Analyst stage. Condensed port of the old
/// <c>email_analyst/prompts.py</c>: the ReAct loop narration is dropped (the
/// deterministic state machine owns routing now) and the response contract is
/// tightened to exactly the fields <see cref="EmailAnalysisResponseParser"/>
/// accepts. Self-reflection and MITRE mapping move to synthesis (Step 8).
/// </summary>
public static class EmailAnalystPrompts
{
    public const string SystemPrompt = """
        You are the Email Analyst of Vigil, a banking security threat detection system.
        You analyze email content (.eml) to detect phishing and social engineering.

        The email has already passed a static rule filter and is PII-redacted
        ([REDACTED_*] placeholders). Pre-computed tool output is provided below;
        you may call the EmailTools functions if you need the payload parsed differently.

        Respond with ONLY a JSON object matching this contract — no markdown fences,
        no commentary:

        {
          "status": "phishing" | "suspicious" | "safe",
          "confidence": <number between 0.0 and 1.0>,
          "iocs": [{"type": "url" | "domain" | "ip" | "email" | "hash", "value": "<string>"}],
          "phishing_indicators": ["<short indicator>", ...],
          "summary": "<2-4 sentence analyst summary>"
        }

        Rules:
        - Only report IOCs that actually appear in the payload or tool output. Do not invent IOCs.
        - Base the verdict on evidence: authentication failures, urgency language, lookalike
          domains, IP-based URLs, credential requests.
        - "safe" requires absence of suspicious signals, not absence of proof.
        """;

    /// <summary>Sent after a malformed response; exactly one retry is attempted.</summary>
    public const string RetryInstruction =
        "Your previous response was not valid JSON matching the required schema. " +
        "Respond with ONLY the JSON object — no markdown fences, no commentary.";

    /// <summary>Builds the user message: rule context + tool output + payload.</summary>
    public static string BuildUserPrompt(
        string scrubbedPayload,
        IReadOnlyCollection<string> matchedRules,
        string toolOutputJson,
        int maxPayloadChars = 4000)
    {
        var payload = scrubbedPayload.Length > maxPayloadChars
            ? scrubbedPayload[..maxPayloadChars] + "\n[... truncated ...]"
            : scrubbedPayload;
        var rules = matchedRules.Count > 0 ? string.Join(", ", matchedRules) : "none";

        return $"""
            Analyze this email for phishing indicators.

            Tier 1 static filter matched rules: {rules}

            Pre-computed tool output (parsed structure + extracted network entities):
            {toolOutputJson}

            Email content (PII-redacted):
            {payload}

            Provide your final analysis as the JSON object described in the system instructions.
            """;
    }
}
