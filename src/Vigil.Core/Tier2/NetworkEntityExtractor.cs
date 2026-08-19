using System.Text.RegularExpressions;

namespace Vigil.Core.Tier2;

/// <summary>
/// URL/domain/IPv4 extraction for the Tier 2 email tools, ported from the old
/// <c>email_analyst/tools.py</c> (extract_network_entities). Without
/// tldextract, "domain" means the URL host; text-level domains come from a
/// hostname regex, mirroring <c>EmailRuleChecks</c>.
/// </summary>
public static partial class NetworkEntityExtractor
{
    public sealed record Entities(IReadOnlyList<string> Urls, IReadOnlyList<string> Domains, IReadOnlyList<string> Ips);

    public static Entities Extract(string text)
    {
        var urls = UrlRegex().Matches(text)
            .Select(m => m.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var domains = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var url in urls)
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                domains.Add(uri.Host);
            }
        }
        foreach (Match match in HostnameRegex().Matches(text))
        {
            domains.Add(match.Value);
        }

        var ips = Ipv4Regex().Matches(text)
            .Select(m => m.Value)
            .Distinct()
            .ToList();

        return new Entities(urls, [.. domains], ips);
    }

    [GeneratedRegex(@"https?://[^\s""'<>\]\)]+", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", RegexOptions.Compiled)]
    private static partial Regex HostnameRegex();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();
}
