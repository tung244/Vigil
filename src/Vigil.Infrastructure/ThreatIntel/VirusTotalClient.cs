using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Vigil.Core.Domain;

namespace Vigil.Infrastructure.ThreatIntel;

/// <summary>
/// VirusTotal API v3 lookups: /ip_addresses/{ip}, /domains/{domain},
/// /urls/{base64url}, /files/{hash}. MaliciousScore = malicious / total from
/// <c>last_analysis_stats</c>. Never throws for API/network failures — returns
/// <see cref="ClientLookup.Fail"/> with a machine-readable reason instead.
/// </summary>
public sealed class VirusTotalClient(
    HttpClient http,
    ThreatIntelOptions options,
    ILogger<VirusTotalClient> logger)
{
    public const string BaseUrl = "https://www.virustotal.com/api/v3/";

    public async Task<ClientLookup> LookupAsync(IocType type, string value, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(options.VirusTotalApiKey))
            return ClientLookup.Fail("missing_api_key");

        var path = type switch
        {
            IocType.Ip => $"ip_addresses/{Uri.EscapeDataString(value)}",
            IocType.Domain => $"domains/{Uri.EscapeDataString(value)}",
            IocType.Url => $"urls/{ToUrlId(value)}",
            IocType.Hash => $"files/{Uri.EscapeDataString(value)}",
            _ => null
        };
        if (path is null)
            return ClientLookup.Fail($"unsupported_ioc_type:{type}");

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, BaseUrl + path);
            request.Headers.Add("x-apikey", options.VirusTotalApiKey);
            using var response = await http.SendAsync(request, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            // 400/404 are definitive answers ("invalid IOC" / "not in VT
            // database"), not failures: score 0, still counts as a live lookup.
            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound)
            {
                return ClientLookup.Ok(0.0, JsonSerializer.Serialize(new
                {
                    source = "VirusTotal",
                    ioc = value,
                    note = "not_found_in_virustotal",
                    http_status = (int)response.StatusCode
                }));
            }

            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("VirusTotal lookup for {Ioc} failed with HTTP {Status}",
                    value, (int)response.StatusCode);
                return ClientLookup.Fail($"http_{(int)response.StatusCode}");
            }

            return ParseAnalysisStats(value, body);
        }
        catch (TaskCanceledException)
        {
            logger.LogWarning("VirusTotal lookup for {Ioc} timed out", value);
            return ClientLookup.Fail("timeout");
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "VirusTotal lookup for {Ioc} hit a network error", value);
            return ClientLookup.Fail("network_error");
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "VirusTotal lookup for {Ioc} returned malformed JSON", value);
            return ClientLookup.Fail("malformed_response");
        }
    }

    private static ClientLookup ParseAnalysisStats(string value, string body)
    {
        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("data", out var data)
            || !data.TryGetProperty("attributes", out var attributes)
            || !attributes.TryGetProperty("last_analysis_stats", out var stats))
        {
            return ClientLookup.Fail("missing_last_analysis_stats");
        }

        long total = 0, malicious = 0;
        foreach (var stat in stats.EnumerateObject())
        {
            var count = stat.Value.ValueKind == JsonValueKind.Number ? stat.Value.GetInt64() : 0;
            total += count;
            if (stat.Name == "malicious")
                malicious = count;
        }

        var score = total > 0 ? (double)malicious / total : 0.0;
        return ClientLookup.Ok(score, body);
    }

    /// <summary>VT URL identifier: base64url of the URL, padding stripped.</summary>
    internal static string ToUrlId(string url) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
