using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Infrastructure.ThreatIntel;

namespace Vigil.UnitTests.ThreatIntel;

public class VirusTotalClientTests
{
    private const string ApiKey = "test-vt-key";

    private static VirusTotalClient CreateClient(HttpMessageHandler handler, string apiKey = ApiKey) =>
        new(new HttpClient(handler),
            new ThreatIntelOptions { VirusTotalApiKey = apiKey },
            NullLogger<VirusTotalClient>.Instance);

    private static HttpResponseMessage VtStatsResponse(int malicious, int suspicious, int harmless, int undetected) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(System.Text.Json.JsonSerializer.Serialize(new
            {
                data = new
                {
                    attributes = new
                    {
                        last_analysis_stats = new { malicious, suspicious, harmless, undetected }
                    }
                }
            }))
        };

    [Fact]
    public async Task Ip_200_parses_last_analysis_stats_to_score()
    {
        // total = 5 + 2 + 70 + 13 = 90 → score 5/90
        var handler = new StubHttpMessageHandler(_ => VtStatsResponse(5, 2, 70, 13));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Ip, "8.8.8.8");

        Assert.True(result.Success);
        Assert.Equal(5.0 / 90.0, result.Score, precision: 6);
        Assert.Contains("last_analysis_stats", result.RawJson);
        Assert.Equal("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal(ApiKey, handler.LastRequest.Headers.GetValues("x-apikey").Single());
    }

    [Fact]
    public async Task Domain_and_hash_map_to_their_v3_endpoints()
    {
        var handler = new StubHttpMessageHandler(_ => VtStatsResponse(0, 0, 90, 0));
        var client = CreateClient(handler);

        await client.LookupAsync(IocType.Domain, "evil.example");
        Assert.Equal("https://www.virustotal.com/api/v3/domains/evil.example",
            handler.LastRequest!.RequestUri!.ToString());

        await client.LookupAsync(IocType.Hash, "abc123");
        Assert.Equal("https://www.virustotal.com/api/v3/files/abc123",
            handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task Url_lookup_uses_base64url_identifier()
    {
        var handler = new StubHttpMessageHandler(_ => VtStatsResponse(0, 0, 90, 0));
        var client = CreateClient(handler);
        const string url = "https://evil.example/login?next=/account";

        await client.LookupAsync(IocType.Url, url);

        var expectedId = VirusTotalClient.ToUrlId(url);
        Assert.Matches("^[A-Za-z0-9\\-_]+$", expectedId);
        Assert.Equal($"https://www.virustotal.com/api/v3/urls/{expectedId}",
            handler.LastRequest!.RequestUri!.ToString());
    }

    [Fact]
    public async Task Not_found_404_is_a_live_zero_score_not_a_fallback()
    {
        var handler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("""{"error":{"code":"NotFoundError"}}""")
        });
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Domain, "nonexistent.invalid");

        Assert.True(result.Success);
        Assert.Equal(0.0, result.Score);
        Assert.Contains("not_found_in_virustotal", result.RawJson);
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
    public async Task Network_error_returns_failure_for_fallback()
    {
        var handler = new StubHttpMessageHandler(_ => throw new HttpRequestException("dns boom"));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.False(result.Success);
        Assert.Equal("network_error", result.FailureReason);
    }

    [Fact]
    public async Task Missing_api_key_short_circuits_without_http_call()
    {
        var handler = new StubHttpMessageHandler(_ => VtStatsResponse(50, 0, 40, 0));
        var client = CreateClient(handler, apiKey: "");

        var result = await client.LookupAsync(IocType.Ip, "1.2.3.4");

        Assert.False(result.Success);
        Assert.Equal("missing_api_key", result.FailureReason);
        Assert.Equal(0, handler.CallCount);
    }

    [Fact]
    public async Task Unsupported_type_returns_failure_without_http_call()
    {
        var handler = new StubHttpMessageHandler(_ => VtStatsResponse(0, 0, 90, 0));
        var client = CreateClient(handler);

        var result = await client.LookupAsync(IocType.Email, "a@b.example");

        Assert.False(result.Success);
        Assert.Equal("unsupported_ioc_type:Email", result.FailureReason);
        Assert.Equal(0, handler.CallCount);
    }
}
