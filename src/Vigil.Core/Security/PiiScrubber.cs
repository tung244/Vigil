using System.Text.RegularExpressions;

namespace Vigil.Core.Security;

/// <summary>
/// Masks personally identifiable information (PII) and sensitive data before an
/// artifact is stored as the scrubbed payload or shown to an LLM agent.
/// Ported from the Python <c>bastion/services/pii_scrubber.py</c>, extended to
/// redact all IPv4/IPv6 addresses (not just RFC 1918) per the rebuild spec.
/// Lives in Vigil.Core because it is a pure text transformation with no
/// infrastructure dependencies; the Worker and any future agent code share it.
/// </summary>
public static partial class PiiScrubber
{
    // Order matters: more specific digit patterns (card, SSN) run before the
    // greedy phone pattern so a card number is not partially eaten as phones.
    private static readonly (Regex Pattern, string Replacement)[] Rules =
    [
        (AwsAccessKeyRegex(), "[REDACTED_AWS_KEY]"),
        (AwsSecretKeyRegex(), "[REDACTED_AWS_SECRET]"),
        (CreditCardRegex(), "[REDACTED_CARD]"),
        (SsnRegex(), "[REDACTED_SSN]"),
        (EmailRegex(), "[REDACTED_EMAIL]"),
        (Ipv4Regex(), "[REDACTED_IP]"),
        (PhoneRegex(), "[REDACTED_PHONE]"),
    ];

    /// <summary>
    /// Applies all PII patterns to <paramref name="text"/> and returns the
    /// redacted copy. Never returns null; null/empty input passes through.
    /// </summary>
    public static string Scrub(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var result = text!;

        // IPv6 first: a candidate validator keeps false positives (times like
        // "14:05:00") out while covering full and compressed forms.
        result = Ipv6CandidateRegex().Replace(result, static m =>
            m.Value.Contains(':', StringComparison.Ordinal)
            && m.Value.Any(char.IsLetterOrDigit)
            && System.Net.IPAddress.TryParse(m.Value, out var ip)
            && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? "[REDACTED_IP]"
                : m.Value);

        foreach (var (pattern, replacement) in Rules)
        {
            result = pattern.Replace(result, replacement);
        }

        // Account IDs are only redacted with explicit context so 12-digit
        // timestamps and the like survive. The surrounding prefix is kept.
        result = AwsAccountIdRegex().Replace(result, static m =>
            m.Value.Replace(m.Groups[1].Value, "[REDACTED_ACCOUNT_ID]", StringComparison.Ordinal));

        return result;
    }

    [GeneratedRegex(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", RegexOptions.Compiled)]
    private static partial Regex AwsAccessKeyRegex();

    [GeneratedRegex(@"(?<=['""\s=:])[A-Za-z0-9/+=]{40}(?=['""\s,}]|$)", RegexOptions.Compiled)]
    private static partial Regex AwsSecretKeyRegex();

    [GeneratedRegex(@"\b(?:\d{4}[\s\-]?){3}\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex CreditCardRegex();

    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled)]
    private static partial Regex SsnRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled)]
    private static partial Regex EmailRegex();

    // Octet-validated IPv4 (0-255 per octet) so "999.1.1.1" is left alone.
    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    // Broad IPv6 candidate (2+ colon-separated hex groups); validated by IPAddress.TryParse.
    [GeneratedRegex(@"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", RegexOptions.Compiled)]
    private static partial Regex Ipv6CandidateRegex();

    // Requires at least one separator so plain long digit runs (IDs, timestamps)
    // are not mistaken for phone numbers.
    [GeneratedRegex(@"(?<!\d)(?:\+?\d{1,3}[\s\-])?(?:\(?\d{2,4}\)?[\s\-])?\d{3,4}[\s\-]\d{4}(?!\d)", RegexOptions.Compiled)]
    private static partial Regex PhoneRegex();

    [GeneratedRegex(@"(?:account[_\-\s]?(?:id)?|arn:aws)[:\s""']*(\d{12})\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex AwsAccountIdRegex();
}
