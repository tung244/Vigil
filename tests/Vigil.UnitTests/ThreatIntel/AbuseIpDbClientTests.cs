using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Infrastructure.ThreatIntel;

namespace Vigil.UnitTests.ThreatIntel;

public class AbuseIpDbClientTests
{
    private const string ApiKey = "test-abuse-key";

    private static AbuseIpDbClient CreateClient(HttpMessageHandler handler, string apiKey = ApiKey) =>
        new(new HttpClient(handler),
            new ThreatIntelOptions { AbuseIpDbApiKey = apiKey },
            NullLogger<AbuseIpDbClient>.Instance);

    private static HttpResponseMessage CheckResponse(int abuseConfidenceScore) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new
            {
                data = new
                {
                    ipAddress = "1.2.3.4",
                    abuseConfidenceScore,
                    totalReports = 12,
                    countryCode = "RU",
                    isp = "BadHost"
                }
            }))
        };

    [Fact]
    public async Task Ip_200_parses_abuse_confidence_score_normalized()
    {
        var handler = new StubHttpMessageHandler(_ => CheckResponse(85));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.True(result.Success);
        Assert.Equal(0.85, result.Score, precision: 6);
        Assert.Contains("abuseConfidenceScore", result.RawJson);
        Assert.Equal(ApiKey, handler.LastRequest!.Headers.GetValues("Key").Single());
        Assert.Equal("1.2.3.4",
            System.Web.HttpUtility.ParseQueryString(handler.LastRequest.RequestUri!.Query)["ipAddress"]);
    }

    [Fact]
    public async Task Rate_limit_429_returns_failure_for_fallback()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)429));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.False(result.Success);
        Assert.Equal("http_429", result.FailureReason);
    }

    [Fact]
    public async Task Timeout_returns_failure_for_fallback()
    {
        var handler = new StubHttpMessageHandler(_ => throw new TaskCanceledException("simulated timeout"));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.False(result.Success);
        Assert.Equal("timeout", result.FailureReason);
    }

    [Fact]
    public async Task Missing_api_key_short_circuits_without_http_call()
    {
        var handler = new StubHttpMessageHandler(_ => CheckResponse(100));
        var client = CreateClient(handler, apiKey: "");

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.False(result.Success);
        Assert.Equal("missing_api_key", result.FailureReason);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task Non_ip_type_is_rejected_without_http_call()
    {
        var handler = new StubHttpMessageHandler(_ => CheckResponse(0));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Domain, "evil.example");

        Assert.False(result.Success);
        Assert.Equal("unsupported_ioc_type:Domain", result.FailureReason);
        Assert.Equal(0, handler.CallCount);
    }
}
