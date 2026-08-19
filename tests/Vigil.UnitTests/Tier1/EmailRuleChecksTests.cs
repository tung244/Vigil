using Vigil.Core.Domain;
using Vigil.Core.Tier1;
using Xunit;

namespace Vigil.UnitTests.Tier1;

public class EmailRuleChecksTests
{
    private static string Eml(
        string from = "alice@example.com",
        string subject = "Quarterly report",
        string body = "Here is the report you asked for.",
        string? authResults = null,
        string? extraHeaders = null) =>
        $"From: \"Alice\" <{from}>\n" +
        $"To: bob@example.com\n" +
        $"Subject: {subject}\n" +
        (authResults is null ? "" : $"Authentication-Results: {authResults}\n") +
        (extraHeaders is null ? "" : extraHeaders + "\n") +
        $"\n{body}\n";

    // ── Authentication-Results ──────────────────────────────────────────

    [Fact]
    public void Flags_spf_dkim_dmarc_failures()
    {
        var report = EmailRuleChecks.Analyze(Eml(
            authResults: "mx.example.com; spf=fail smtp.mailfrom=evil.example; dkim=fail; dmarc=fail"));

        Assert.Contains("spf_fail", report.MatchedRules);
        Assert.Contains("dkim_fail", report.MatchedRules);
        Assert.Contains("dmarc_fail", report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public void Flags_spf_softfail()
    {
        var report = EmailRuleChecks.Analyze(Eml(authResults: "mx; spf=softfail"));

        Assert.Contains("spf_fail", report.MatchedRules);
        Assert.DoesNotContain("dkim_fail", report.MatchedRules);
    }

    [Fact]
    public void Passing_auth_results_produce_no_rules()
    {
        var report = EmailRuleChecks.Analyze(Eml(authResults: "mx; spf=pass; dkim=pass; dmarc=pass"));

        Assert.Empty(report.MatchedRules);
        Assert.Equal(Tier1Verdict.Benign, report.Verdict);
        Assert.All(report.Checks.Where(c => c.Name.StartsWith("auth_", StringComparison.Ordinal)),
            c => Assert.Equal("pass", c.Result));
    }

    [Fact]
    public void Missing_auth_results_header_is_neutral()
    {
        var report = EmailRuleChecks.Analyze(Eml());

        Assert.Empty(report.MatchedRules);
        Assert.All(report.Checks.Where(c => c.Name.StartsWith("auth_", StringComparison.Ordinal)),
            c => Assert.Equal("not_present", c.Result));
    }

    // ── Keyword rules ───────────────────────────────────────────────────

    [Theory]
    [InlineData("Urgent: verify your account", "urgent_action_required")]
    [InlineData("Please verify your account today", "verify_account")]
    [InlineData("Your account suspended immediately", "suspended_account")]
    [InlineData("Click here to claim your prize", "click_link")]
    [InlineData("Enter your password to continue", "credential_harvest")]
    [InlineData("Reset your password within 24 hours", "password_reset")]
    public void Flags_phishing_keywords(string subject, string expectedRule)
    {
        var report = EmailRuleChecks.Analyze(Eml(subject: subject));

        Assert.Contains(expectedRule, report.MatchedRules);
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    // ── Sender domain checks ────────────────────────────────────────────

    [Theory]
    [InlineData("paypa1.com")]        // leetspeak
    [InlineData("paypal-secure.xyz")] // brand + high-risk pattern
    [InlineData("micros0ft-login.com")]
    public void Flags_lookalike_sender_domains(string domain)
    {
        var report = EmailRuleChecks.Analyze(Eml(from: $"support@{domain}"));

        Assert.Contains(report.MatchedRules, r =>
            r.StartsWith("lookalike_domain:", StringComparison.Ordinal)
            || r.StartsWith("suspicious_domain:", StringComparison.Ordinal));
        Assert.Equal(Tier1Verdict.Suspicious, report.Verdict);
    }

    [Theory]
    [InlineData("paypal.com")]          // official
    [InlineData("mail.paypal.com")]     // official subdomain
    [InlineData("amazonaws.com")]       // official AWS domain contains "amazon"
    [InlineData("example.com")]         // unrelated
    public void Clean_sender_domains_are_not_flagged(string domain)
    {
        var report = EmailRuleChecks.Analyze(Eml(from: $"support@{domain}"));

        Assert.DoesNotContain(report.MatchedRules, r =>
            r.StartsWith("lookalike_domain:", StringComparison.Ordinal)
            || r.StartsWith("suspicious_domain:", StringComparison.Ordinal));
    }

    [Fact]
    public void Flags_suspicious_pattern_domain()
    {
        var report = EmailRuleChecks.Analyze(Eml(from: "alerts@secure-banking-login.com"));

        Assert.Contains(report.MatchedRules,
            r => r == "suspicious_domain:secure-banking-login.com");
    }

    // ── URL / IP extraction ─────────────────────────────────────────────

    [Fact]
    public void Flags_ip_based_urls_and_extracts_entities()
    {
        var report = EmailRuleChecks.Analyze(Eml(
            body: "Login at http://198.51.100.23/verify or visit https://example.com/help"));

        Assert.Contains("ip_in_url_detected", report.MatchedRules);
        Assert.Contains("http://198.51.100.23/verify", (IEnumerable<string>)report.Extracted["urls"]!);
        Assert.Contains("198.51.100.23", (IEnumerable<string>)report.Extracted["ips"]!);
        Assert.Equal("example.com", report.Extracted["senderDomain"]);
    }

    [Fact]
    public void Extracts_ips_from_received_headers()
    {
        var report = EmailRuleChecks.Analyze(Eml(
            extraHeaders: "Received: from mail.evil.example ([203.0.113.7]) by mx.example.com;\n"
                + "\tTue, 24 Mar 2026 10:00:00 +0700"));

        Assert.Contains("203.0.113.7", (IEnumerable<string>)report.Extracted["headerIps"]!);
    }

    // ── Benign baseline ─────────────────────────────────────────────────

    [Fact]
    public void Benign_email_scores_zero_and_passes()
    {
        var report = EmailRuleChecks.Analyze(Eml(
            authResults: "mx; spf=pass; dkim=pass; dmarc=pass"));

        Assert.Equal(Tier1Verdict.Benign, report.Verdict);
        Assert.Empty(report.MatchedRules);
        Assert.Equal(0, report.RiskScore);
        Assert.Equal("alice@example.com", report.Extracted["sender"]);
    }

    [Fact]
    public void Header_continuation_lines_are_unfolded()
    {
        var message = EmlParser.Parse(
            "From: a@example.com\nSubject: very long subject\n\tcontinued here\n\nbody");

        Assert.Equal("very long subject continued here", message.Subject);
    }
}
