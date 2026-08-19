using Vigil.Core.Security;
using Xunit;

namespace Vigil.UnitTests.Security;

public class PiiScrubberTests
{
    // ── IPv4 ────────────────────────────────────────────────────────────

    [Fact]
    public void Scrubs_public_ipv4()
    {
        var result = PiiScrubber.Scrub("Connection from 203.0.113.50 refused.");
        Assert.Equal("Connection from [REDACTED_IP] refused.", result);
    }

    [Fact]
    public void Scrubs_internal_ipv4()
    {
        var result = PiiScrubber.Scrub("hosts 10.0.0.1, 172.16.5.4 and 192.168.1.1");
        Assert.Equal("hosts [REDACTED_IP], [REDACTED_IP] and [REDACTED_IP]", result);
    }

    [Theory]
    [InlineData("999.1.1.1")]
    [InlineData("256.300.1.1")]
    [InlineData("10.0.0")]
    public void Leaves_invalid_ipv4_alone(string notAnIp)
    {
        Assert.Equal(notAnIp, PiiScrubber.Scrub(notAnIp));
    }

    // ── IPv6 ────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("2001:0db8:85a3:0000:0000:8a2e:0370:7334")]
    [InlineData("2001:db8::1")]
    [InlineData("::1")]
    [InlineData("fe80::1ff:fe23:4567:890a")]
    public void Scrubs_ipv6(string ip)
    {
        Assert.Equal("[REDACTED_IP]", PiiScrubber.Scrub(ip));
    }

    [Theory]
    [InlineData("14:05:00")] // time of day
    [InlineData("step 1: do this: then that")] // prose colons
    public void Leaves_colon_separated_non_ips_alone(string text)
    {
        Assert.Equal(text, PiiScrubber.Scrub(text));
    }

    // ── Email ───────────────────────────────────────────────────────────

    [Fact]
    public void Scrubs_email_addresses()
    {
        var result = PiiScrubber.Scrub("Contact john.doe+alerts@mail.example.com for details.");
        Assert.Equal("Contact [REDACTED_EMAIL] for details.", result);
    }

    [Fact]
    public void Leaves_bare_at_sign_alone()
    {
        Assert.Equal("meet @ noon", PiiScrubber.Scrub("meet @ noon"));
    }

    // ── Phone ───────────────────────────────────────────────────────────

    [Theory]
    [InlineData("call +1-202-555-0143 now", "call [REDACTED_PHONE] now")]
    [InlineData("call (202) 555-0143 now", "call [REDACTED_PHONE] now")]
    [InlineData("call 202-555-0143 now", "call [REDACTED_PHONE] now")]
    [InlineData("call +44 20 7946 0958 now", "call [REDACTED_PHONE] now")]
    public void Scrubs_phone_numbers(string input, string expected)
    {
        Assert.Equal(expected, PiiScrubber.Scrub(input));
    }

    // ── Cards / IDs ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("card 4111 1111 1111 1111 end", "card [REDACTED_CARD] end")]
    [InlineData("card 4111-1111-1111-1111 end", "card [REDACTED_CARD] end")]
    [InlineData("card 4111111111111111 end", "card [REDACTED_CARD] end")]
    public void Scrubs_card_numbers_without_phone_leftovers(string input, string expected)
    {
        var result = PiiScrubber.Scrub(input);
        Assert.Equal(expected, result);
        Assert.DoesNotContain("[REDACTED_PHONE]", result);
    }

    [Fact]
    public void Scrubs_ssn()
    {
        Assert.Equal("ssn [REDACTED_SSN] here", PiiScrubber.Scrub("ssn 123-45-6789 here"));
    }

    [Fact]
    public void Scrubs_aws_access_key()
    {
        Assert.Equal("key [REDACTED_AWS_KEY] leaked",
            PiiScrubber.Scrub("key AKIAIOSFODNN7EXAMPLE leaked"));
    }

    [Fact]
    public void Scrubs_account_id_but_keeps_prefix()
    {
        Assert.Equal("account id: [REDACTED_ACCOUNT_ID] owns it",
            PiiScrubber.Scrub("account id: 123456789012 owns it"));
    }

    [Fact]
    public void Leaves_bare_12_digit_number_alone()
    {
        Assert.Equal("id 123456789012 ok", PiiScrubber.Scrub("id 123456789012 ok"));
    }

    // ── General ─────────────────────────────────────────────────────────

    [Fact]
    public void Leaves_clean_text_unchanged()
    {
        const string text = "Daily report: 12 new tickets, all resolved by the team.";
        Assert.Equal(text, PiiScrubber.Scrub(text));
    }

    [Fact]
    public void Handles_null_and_empty()
    {
        Assert.Equal(string.Empty, PiiScrubber.Scrub(null));
        Assert.Equal(string.Empty, PiiScrubber.Scrub(string.Empty));
    }

    [Fact]
    public void Scrubs_multiple_pii_types_in_one_pass()
    {
        var result = PiiScrubber.Scrub(
            "From alice@corp.example (10.1.2.3, +1-202-555-0143) paid with 4111-1111-1111-1111.");
        Assert.Equal(
            "From [REDACTED_EMAIL] ([REDACTED_IP], [REDACTED_PHONE]) paid with [REDACTED_CARD].",
            result);
    }
}
