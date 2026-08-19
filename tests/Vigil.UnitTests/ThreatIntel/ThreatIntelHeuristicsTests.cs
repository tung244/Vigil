using Vigil.Core.Domain;
using Vigil.Infrastructure.ThreatIntel;

namespace Vigil.UnitTests.ThreatIntel;

public class ThreatIntelHeuristicsTests
{
    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.5")]
    [InlineData("172.16.8.4")]
    [InlineData("127.0.0.1")]
    public void Private_ips_score_zero_with_internal_flag(string ip)
    {
        var result = ThreatIntelHeuristics.Score(IocType.Ip, ip);

        Assert.Equal(0.0, result.Score);
        Assert.Equal(["internal_ip"], result.Flags);
    }

    [Fact]
    public void Known_tor_exit_prefix_raises_score()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Ip, "185.220.101.1");

        // 0.40 Tor prefix + 0.15 geo range (first octet 185)
        Assert.Equal(0.55, result.Score, precision: 6);
        Assert.Contains("known_tor_exit_prefix", result.Flags);
        Assert.Contains("high_risk_geo_range", result.Flags);
    }

    [Fact]
    public void Plain_public_ip_scores_zero()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Ip, "8.8.8.8");

        Assert.Equal(0.0, result.Score);
        Assert.Empty(result.Flags);
    }

    [Fact]
    public void Whitelisted_domain_scores_zero()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Domain, "mail.google.com");

        Assert.Equal(0.0, result.Score);
        Assert.Equal(["whitelisted_domain"], result.Flags);
    }

    [Fact]
    public void High_risk_tld_adds_score()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Domain, "random-name.xyz");

        Assert.Equal(0.25, result.Score, precision: 6);
        Assert.Equal(["high_risk_tld:.xyz"], result.Flags);
    }

    [Fact]
    public void Brand_impersonation_pattern_stacks_with_tld()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Domain, "paypal-secure.xyz");

        Assert.Equal(0.55, result.Score, precision: 6);
        Assert.Contains("high_risk_tld:.xyz", result.Flags);
        Assert.Contains("brand_impersonation_pattern", result.Flags);
    }

    [Fact]
    public void Multi_hyphen_domain_adds_score()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Domain, "account-verify-portal.com");

        Assert.Equal(0.15, result.Score, precision: 6);
        Assert.Equal(["multi_hyphen_domain"], result.Flags);
    }

    [Fact]
    public void Url_is_scored_by_its_host()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Url, "http://evil.xyz/login?u=1");

        Assert.Equal(0.25, result.Score, precision: 6);
        Assert.Contains("high_risk_tld:.xyz", result.Flags);
    }

    [Fact]
    public void Hash_has_no_heuristic()
    {
        var result = ThreatIntelHeuristics.Score(IocType.Hash, "d41d8cd98f00b204e9800998ecf8427e");

        Assert.Equal(0.0, result.Score);
        Assert.Empty(result.Flags);
    }
}
