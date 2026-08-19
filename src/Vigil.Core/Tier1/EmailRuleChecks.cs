using System.Text.RegularExpressions;
using Vigil.Core.Domain;

namespace Vigil.Core.Tier1;

/// <summary>
/// Tier 1 rule checks for .eml artifacts, ported from the Python
/// <c>email_analyst/tier1_filter.py</c>: authentication header checks
/// (SPF/DKIM/DMARC), phishing keyword rules, suspicious/lookalike sender
/// domains and URL/IP extraction. The ML classifier score from the old system
/// arrives separately in Step 5 (ONNX).
/// </summary>
public static partial class EmailRuleChecks
{
    private const int SuspiciousDomainScore = 20;

    // Brand token → official domains. A sender domain containing a brand token
    // (after leetspeak normalization) without ending in an official domain is
    // flagged as a lookalike.
    private static readonly (string Brand, string[] OfficialDomains)[] Brands =
    [
        ("paypal", ["paypal.com"]),
        ("chase", ["chase.com"]),
        ("wellsfargo", ["wellsfargo.com"]),
        ("citibank", ["citibank.com", "citi.com"]),
        ("microsoft", ["microsoft.com", "live.com", "outlook.com"]),
        ("apple", ["apple.com", "icloud.com"]),
        ("google", ["google.com", "gmail.com"]),
        ("amazon", ["amazon.com", "amazonaws.com"]),
        ("netflix", ["netflix.com"]),
        ("facebook", ["facebook.com", "fb.com"]),
    ];

    public static Tier1RuleReport Analyze(string rawEml)
    {
        var message = EmlParser.Parse(rawEml);
        var combinedText = $"{message.Subject} {message.Body}";

        var report = new Tier1RuleReport
        {
            ArtifactType = ArtifactType.Eml.ToString(),
            Verdict = Tier1Verdict.Benign
        };

        // 1. Authentication-Results: SPF / DKIM / DMARC.
        var authResults = EmlParser.ParseAuthenticationResults(message);
        foreach (var proto in new[] { "spf", "dkim", "dmarc" })
        {
            if (authResults.TryGetValue(proto, out var result))
            {
                var failed = result is "fail" or "softfail";
                report.Checks.Add(new RuleCheck(
                    $"auth_{proto}", failed ? "fail" : "pass", $"{proto}={result}"));
                if (failed)
                {
                    report.MatchedRules.Add($"{proto}_fail");
                }
            }
            else
            {
                report.Checks.Add(new RuleCheck(
                    $"auth_{proto}", "not_present", "No Authentication-Results entry."));
            }
        }

        // 2. Phishing keyword rules over subject + body.
        foreach (var (name, pattern) in PhishingRules)
        {
            if (pattern.IsMatch(combinedText))
            {
                report.MatchedRules.Add(name);
            }
        }

        // 3. Entity extraction from the body text.
        var urls = UrlRegex().Matches(combinedText).Select(m => m.Value).Distinct().ToList();
        var bodyIps = Ipv4Regex().Matches(combinedText).Select(m => m.Value).Distinct().ToList();
        var domains = DomainRegex().Matches(combinedText).Select(m => m.Value).Distinct().ToList();

        // 4. IPs from Received / X-Originating-IP headers.
        var headerIps = message.GetHeaders("Received")
            .Concat(message.GetHeaders("X-Originating-IP"))
            .SelectMany(h => Ipv4Regex().Matches(h).Select(m => m.Value))
            .Distinct()
            .ToList();

        // 5. Sender address and domain.
        var sender = ExtractSenderAddress(message.From);
        var senderDomain = sender is not null && sender.Contains('@', StringComparison.Ordinal)
            ? sender[(sender.LastIndexOf('@') + 1)..].ToLowerInvariant()
            : null;

        // 6. Suspicious domain patterns over body domains and the sender domain.
        foreach (var domain in domains.Concat(senderDomain is null ? [] : new[] { senderDomain }))
        {
            if (SuspiciousDomainPatterns.Any(p => p.IsMatch(domain)))
            {
                report.MatchedRules.Add($"suspicious_domain:{domain}");
            }
        }

        // 7. Lookalike brand check on the sender domain.
        if (senderDomain is not null && IsLookalikeDomain(senderDomain, out var brand))
        {
            report.MatchedRules.Add($"lookalike_domain:{senderDomain}");
            report.Checks.Add(new RuleCheck(
                "lookalike_domain", "flag",
                $"Sender domain '{senderDomain}' impersonates brand '{brand}'."));
        }
        else
        {
            report.Checks.Add(new RuleCheck(
                "lookalike_domain", "pass",
                senderDomain is null ? "No sender domain." : $"Sender domain '{senderDomain}' is clean."));
        }

        // 8. IP-based URL is a strong phishing signal.
        var ipInUrl = IpInUrlRegex().IsMatch(combinedText);
        report.Checks.Add(new RuleCheck(
            "ip_in_url", ipInUrl ? "flag" : "pass",
            ipInUrl ? "URL with literal IP host found." : "No IP-based URLs."));
        if (ipInUrl)
        {
            report.MatchedRules.Add("ip_in_url_detected");
        }

        report.Extracted["sender"] = sender;
        report.Extracted["senderDomain"] = senderDomain;
        report.Extracted["urls"] = urls;
        report.Extracted["ips"] = bodyIps;
        report.Extracted["domains"] = domains;
        report.Extracted["headerIps"] = headerIps;

        // Same scoring shape as the old system, minus the ML contribution.
        var score = Math.Min(report.MatchedRules.Count * 8, 30)
            + Math.Min(urls.Count * 3, 10)
            + Math.Min(bodyIps.Count * 3, 10)
            + Math.Min(headerIps.Count * 3, 10)
            + (ipInUrl ? 15 : 0)
            + (report.MatchedRules.Any(r => r.StartsWith("suspicious_domain:", StringComparison.Ordinal)
                || r.StartsWith("lookalike_domain:", StringComparison.Ordinal))
                ? SuspiciousDomainScore
                : 0);
        report.RiskScore = Math.Min(score, 100);

        report.ApplyVerdict();
        return report;
    }

    /// <summary>Extracts the bare address from a From header ("Name" &lt;a@b&gt; → a@b).</summary>
    internal static string? ExtractSenderAddress(string? fromHeader)
    {
        if (string.IsNullOrWhiteSpace(fromHeader))
        {
            return null;
        }

        var match = EmailAddressRegex().Match(fromHeader);
        return match.Success ? match.Value : null;
    }

    /// <summary>
    /// True when the domain contains a brand token (leetspeak-normalized)
    /// without being an official domain or subdomain of the brand.
    /// </summary>
    internal static bool IsLookalikeDomain(string domain, out string brand)
    {
        var normalized = NormalizeLeetspeak(domain.ToLowerInvariant());
        foreach (var (candidate, officialDomains) in Brands)
        {
            if (!normalized.Contains(candidate, StringComparison.Ordinal))
            {
                continue;
            }

            if (officialDomains.Any(official =>
                    domain.Equals(official, StringComparison.OrdinalIgnoreCase)
                    || domain.EndsWith("." + official, StringComparison.OrdinalIgnoreCase)))
            {
                continue; // official domain or a subdomain of it
            }

            brand = candidate;
            return true;
        }

        brand = string.Empty;
        return false;
    }

    private static string NormalizeLeetspeak(string value) => value
        .Replace('0', 'o').Replace('1', 'l').Replace('3', 'e')
        .Replace('5', 's').Replace('7', 't').Replace('@', 'a')
        .Replace("$", "s", StringComparison.Ordinal)
        .Replace("vv", "w", StringComparison.Ordinal);

    private static readonly (string Name, Regex Pattern)[] PhishingRules =
    [
        ("urgent_action_required", R(@"\b(urgent|immediate\s+action|act\s+now|action\s+required)\b")),
        ("verify_account", R(@"\b(verify\s+your\s+(account|identity)|confirm\s+your\s+(identity|account))\b")),
        ("password_reset", R(@"\b(reset\s+your\s+password|change\s+your\s+password|password\s+expir)")),
        ("suspended_account", R(@"\b(account\s+(suspended|locked|disabled|compromised|permanently))\b")),
        ("click_link", R(@"\b(click\s+(here|this\s+link|below|the\s+secure\s+link)|follow\s+this\s+link)\b")),
        ("fake_login_page", R(@"\b(login|log\s+in|sign\s+in)\s+(to\s+your|page|portal)\b")),
        ("financial_threat", R(@"\b(bank\s+account|credit\s+card|payment\s+(declined|failed)|unauthorized\s+transaction|wire\s+transfer)\b")),
        ("reward_lure", R(@"\b(you\s+have\s+won|congratulations|claim\s+your\s+(prize|reward|refund))\b")),
        ("personal_info_request", R(@"\b(social\s+security|ssn|date\s+of\s+birth|mother.?s\s+maiden|routing\s+number|account\s+number)\b")),
        ("attachment_lure", R(@"\b(see\s+attached|open\s+the\s+attachment|download\s+the\s+file)\b")),
        ("time_pressure", R(@"\b(within\s+\d+\s+hours?|expires?\s+(today|soon|immediately)|final\s+warning)\b")),
        ("security_alert", R(@"\b(security\s+alert|unusual\s+login|unrecognized\s+device|unauthorized\s+access|suspicious\s+activity)\b")),
        ("credential_harvest", R(@"\b(domain\s+credentials?|enter\s+(your\s+)?(password|credentials?)|log\s*in\s+credentials?)\b")),
        ("impersonation_authority", R(@"\b(federal\s+reserve|regulatory|compliance\s+update|internal\s+audit|ceo|finance\s+officer|SWIFT\s+transfer)\b")),
        ("compliance_pressure", R(@"\b(mandatory|must\s+be\s+applied|require[ds]?\s+.{0,20}update|immediately)\b")),
        ("ip_in_url_lure", R(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")),
        ("device_login_scare", R(@"\b(login\s+from.{0,30}(device|location|IP)|secure\s+your\s+account|review\s+(the|your)\s+logs)\b")),
    ];

    private static Regex R(string pattern) =>
        new(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex[] SuspiciousDomainPatterns =
    [
        R(@"secure-.*login"),
        R(@"(bank|paypal|chase|wells\s?fargo).*\.(xyz|top|tk|ml|ga|cf|pw)"),
        R(@"\d{4,}.*\.(com|net|org)"),
        R(@"[a-z]+-[a-z]+-[a-z]+\.(com|net)"),
        R(@"(vault|portal|desk|reserve|swift).*bank"),
        R(@"bank.*(vault|portal|desk|secure)"),
        R(@"federal-reserve|reserve-notice"),
        R(@"(it-desk|help-?desk).*\.(net|com)"),
        R(@"(swift|ach|wire)-.*\.(com|net)"),
    ];

    [GeneratedRegex(@"https?://[^\s""'<>\]\)]+", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", RegexOptions.Compiled)]
    private static partial Regex DomainRegex();

    [GeneratedRegex(@"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex IpInUrlRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled)]
    private static partial Regex EmailAddressRegex();
}
