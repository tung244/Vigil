using Vigil.Core.Domain;
using Vigil.Core.Tier2;

namespace Vigil.UnitTests.Tier2;

public class EmailAnalysisResponseParserTests
{
    private const string ValidJson = """
        {
          "status": "phishing",
          "confidence": 0.92,
          "iocs": [
            {"type": "url", "value": "https://evil.example/login"},
            {"type": "domain", "value": "evil.example"}
          ],
          "phishing_indicators": ["urgency language", "lookalike domain"],
          "summary": "Credential-harvesting lure impersonating a bank portal."
        }
        """;

    [Fact]
    public void Valid_bare_json_parses_into_a_result()
    {
        var ok = EmailAnalysisResponseParser.TryParse(ValidJson, out var result);

        Assert.True(ok);
        Assert.NotNull(result);
        Assert.Equal(EmailVerdict.Phishing, result!.Status);
        Assert.Equal(0.92, result.Confidence, precision: 6);
        Assert.Equal(2, result.Iocs.Count);
        Assert.Equal(new ExtractedIoc(IocType.Url, "https://evil.example/login"), result.Iocs[0]);
        Assert.Equal(new ExtractedIoc(IocType.Domain, "evil.example"), result.Iocs[1]);
        Assert.Equal(["urgency language", "lookalike domain"], result.PhishingIndicators);
        Assert.Contains("Credential-harvesting", result.Summary);
    }

    [Fact]
    public void Json_inside_a_markdown_fence_with_surrounding_prose_parses()
    {
        var ok = EmailAnalysisResponseParser.TryParse(
            "Here is my analysis:\n```json\n" + ValidJson + "\n```\nHope that helps.", out var result);

        Assert.True(ok);
        Assert.Equal(EmailVerdict.Phishing, result!.Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json at all")]
    [InlineData("{ \"status\": \"phishing\", summary broken")]
    [InlineData("[{\"status\":\"phishing\"}]")]
    public void Malformed_responses_are_rejected(string? raw)
    {
        Assert.False(EmailAnalysisResponseParser.TryParse(raw, out var result));
        Assert.Null(result);
    }

    [Theory]
    // status not in the enum
    [InlineData("""{"status": "maybe", "summary": "x"}""")]
    // missing/empty summary
    [InlineData("""{"status": "phishing"}""")]
    [InlineData("""{"status": "phishing", "summary": "  "}""")]
    public void Contract_violations_are_rejected(string raw)
    {
        Assert.False(EmailAnalysisResponseParser.TryParse(raw, out _));
    }

    [Fact]
    public void Unknown_ioc_types_are_dropped_and_optional_fields_default()
    {
        const string raw = """
            {
              "status": "SUSPICIOUS",
              "iocs": [
                {"type": "carrier-pigeon", "value": "?!"},
                {"type": "ip", "value": "203.0.113.9"},
                {"type": "url"}
              ],
              "summary": "Possibly malicious."
            }
            """;

        var ok = EmailAnalysisResponseParser.TryParse(raw, out var result);

        Assert.True(ok);
        Assert.Equal(EmailVerdict.Suspicious, result!.Status);
        Assert.Equal(0.5, result.Confidence, precision: 6); // default
        Assert.Equal([new ExtractedIoc(IocType.Ip, "203.0.113.9")], result.Iocs);
        Assert.Empty(result.PhishingIndicators);
    }

    [Fact]
    public void Confidence_is_clamped_into_range()
    {
        var ok = EmailAnalysisResponseParser.TryParse(
            """{"status": "safe", "confidence": 7.5, "summary": "Clean."}""", out var result);

        Assert.True(ok);
        Assert.Equal(1.0, result!.Confidence, precision: 6);
    }
}
