using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;

namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// AbuseIPDB API v2: GET /check?ipAddress= → MaliciousScore =
/// abuseConfidenceScore / 100. IP lookups only. Never throws for API/network
/// failures — returns <see cref="ClientLookup.Fail"/> instead.
/// </summary>
public sealed class AbuseIpDbClient(
    HttpClient http,
    ThreatIntelOptions options,
    ILogger<AbuseIpDbClient> logger)
{
    public const string BaseUrl = "https://api.abuseipdb.com/api/v2/";

    public async Task<ClientLookup> LookupAsync(IocType type, string value, CancellationToken cancellationToken = default)
    {
        if (type != IocType.Ip)
            return ClientLookup.Fail($"unsupported_ioc_type:{type}");

        if (string.IsNullOrWhiteSpace(options.AbuseIpDbApiKey))
            return ClientLookup.Fail("missing_api_key");

        try
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"{BaseUrl}check?ipAddress={Uri.EscapeDataString(value)}&maxAgeInDays=90");
            request.Headers.TryAddWithoutValidation("Key", options.AbuseIpDbApiKey);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await http.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("AbuseIPDB lookup for {Ip} failed with HTTP {Status}",
                    value, (int)response.StatusCode);
                return ClientLookup.Fail($"http_{(int)response.StatusCode}");
            }

            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var data)
                || !data.TryGetProperty("abuseConfidenceScore", out var scoreElement)
                || scoreElement.ValueKind != JsonValueKind.Number)
            {
                return ClientLookup.Fail("missing_abuse_confidence_score");
            }

            var score = Math.Clamp(scoreElement.GetInt32() / 100.0, 0.0, 1.0);
            return ClientLookup.Ok(score, body);
        }
        catch (TaskCanceledException)
        {
            logger.LogWarning("AbuseIPDB lookup for {Ip} timed out", value);
            return ClientLookup.Fail("timeout");
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "AbuseIPDB lookup for {Ip} hit a network error", value);
            return ClientLookup.Fail("network_error");
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "AbuseIPDB lookup for {Ip} returned malformed JSON", value);
            return ClientLookup.Fail("malformed_response");
        }
    }
}
