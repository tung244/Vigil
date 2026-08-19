using System.Text.RegularExpressions;
using Vigil.Core.Domain;

namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// Heuristic IOC scoring used when the live APIs are unavailable (no key,
/// rate limited, timeout, network error). Ported from the Python reference
/// (bastion/agents/threat_intel/tools.py): RFC 1918 skip, known Tor exit
/// prefixes, high-risk TLDs, brand-impersonation patterns, multi-hyphen
/// domains. Scores are normalized to 0.0–1.0.
/// </summary>
public static class ThreatIntelHeuristics
{
    public sealed record HeuristicScore(double Score, string[] Flags);

    private static readonly string[] KnownTorExitPrefixes =
    [
        "185.220.", "185.129.", "176.10.", "198.98.", "195.176.",
        "62.210.", "51.15.", "163.172.", "212.47.", "151.115."
    ];

    private static readonly HashSet<string> HighRiskTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "xyz", "top", "tk", "ml", "ga", "cf", "pw", "buzz", "club",
        "work", "icu", "cam", "rest", "surf", "monster", "loan"
    };

    private static readonly Regex[] MaliciousPatterns =
    [
        new(@"(bank|paypal|chase|wells.?fargo|citi|secure.?login)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(phishing|malware|exploit|ransomware|c2|command.?control)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled)
    ];

    private static readonly HashSet<string> WhitelistDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "google.com", "microsoft.com", "amazon.com", "apple.com",
        "cloudflare.com", "amazonaws.com", "azure.com", "github.com",
        "office.com", "outlook.com", "live.com", "facebook.com",
        "twitter.com", "linkedin.com", "akamai.com", "fastly.com"
    };

    private static readonly Regex Ipv4Pattern =
        new(@"^\d{1,3}(\.\d{1,3}){3}$", RegexOptions.Compiled);

    private static readonly Regex Rfc1918Pattern = new(
        @"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        + @"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        + @"|192\.168\.\d{1,3}\.\d{1,3}"
        + @"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
        RegexOptions.Compiled);

    public static HeuristicScore Score(IocType type, string value)
    {
        var (score, flags) = type switch
        {
            IocType.Ip => ScoreIp(value),
            IocType.Domain => ScoreDomain(value),
            IocType.Url => ScoreUrl(value),
            // No meaningful heuristic for bare hashes or email addresses.
            _ => (0.0, Array.Empty<string>())
        };
        return new HeuristicScore(Math.Clamp(score, 0.0, 1.0), flags);
    }

    private static (double Score, string[] Flags) ScoreIp(string ip)
    {
        if (Rfc1918Pattern.IsMatch(ip))
            return (0.0, ["internal_ip"]);

        double score = 0.0;
        var flags = new List<string>();

        if (KnownTorExitPrefixes.Any(ip.StartsWith))
        {
            score += 0.40;
            flags.Add("known_tor_exit_prefix");
        }

        // Rough geo heuristic from the Python port: these first-octet ranges
        // stand in for high-risk geographies in demo mode.
        if (Ipv4Pattern.IsMatch(ip) && int.TryParse(ip.Split('.')[0], out var firstOctet)
            && (firstOctet is >= 176 and <= 185 || firstOctet is >= 36 and <= 41))
        {
            score += 0.15;
            flags.Add("high_risk_geo_range");
        }

        return (score, flags.ToArray());
    }

    private static (double Score, string[] Flags) ScoreUrl(string url)
    {
        // tldextract in the Python version handles full URLs; here we pull the
        // host out and run the domain logic on it.
        var host = Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
        return ScoreDomain(host);
    }

    private static (double Score, string[] Flags) ScoreDomain(string domain)
    {
        var labels = domain.Trim().TrimEnd('.').Split('.',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (labels.Length == 0)
            return (0.0, []);

        // Registered domain approximation: last two labels (good enough for the
        // whitelist/TLD heuristics; no public-suffix list in demo mode).
        var tld = labels[^1];
        var registered = labels.Length >= 2
            ? $"{labels[^2]}.{labels[^1]}"
            : labels[0];

        if (WhitelistDomains.Contains(registered))
            return (0.0, ["whitelisted_domain"]);

        double score = 0.0;
        var flags = new List<string>();

        if (HighRiskTlds.Contains(tld))
        {
            score += 0.25;
            flags.Add($"high_risk_tld:.{tld.ToLowerInvariant()}");
        }

        if (MaliciousPatterns.Any(p => p.IsMatch(domain)))
        {
            score += 0.30;
            flags.Add("brand_impersonation_pattern");
        }

        if (labels.Length >= 2 && labels[^2].Count(c => c == '-') >= 2)
        {
            score += 0.15;
            flags.Add("multi_hyphen_domain");
        }

        return (score, flags.ToArray());
    }
}
