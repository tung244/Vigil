using System.Text.Json;
using System.Text.Json.Serialization;
using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>
/// Strict parser for the Email Analyst LLM response. The LLM is instructed to
/// answer with a single JSON object (see <see cref="EmailAnalystPrompts"/>);
/// this parser accepts the bare object or one wrapped in a markdown fence and
/// rejects everything else. Strict on shape (valid JSON, known verdict,
/// non-empty summary), lenient on content (unknown IOC types are dropped,
/// missing optional fields get defaults).
/// </summary>
public static partial class EmailAnalysisResponseParser
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static bool TryParse(string? rawResponse, out EmailAnalysisResult? result)
    {
        result = null;
        var json = ExtractJsonObject(rawResponse);
        if (json is null)
        {
            return false;
        }

        ResponseDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<ResponseDto>(json, JsonOptions);
        }
        catch (JsonException)
        {
            return false;
        }

        if (dto is null
            || !Enum.TryParse<EmailVerdict>(dto.Status, ignoreCase: true, out var status)
            || string.IsNullOrWhiteSpace(dto.Summary))
        {
            return false;
        }

        var iocs = new List<ExtractedIoc>();
        foreach (var ioc in dto.Iocs ?? [])
        {
            if (Enum.TryParse<IocType>(ioc.Type, ignoreCase: true, out var type)
                && !string.IsNullOrWhiteSpace(ioc.Value))
            {
                iocs.Add(new ExtractedIoc(type, ioc.Value.Trim()));
            }
        }

        result = new EmailAnalysisResult
        {
            Status = status,
            Confidence = Math.Clamp(dto.Confidence ?? 0.5, 0.0, 1.0),
            Iocs = iocs,
            PhishingIndicators = (dto.PhishingIndicators ?? [])
                .Where(i => !string.IsNullOrWhiteSpace(i)).ToList(),
            Summary = dto.Summary.Trim()
        };
        return true;
    }

    /// <summary>
    /// Extracts the JSON object from an LLM response: prefers a markdown code
    /// fence, falls back to the outermost { ... } span (same strategy as the
    /// old Python <c>_extract_json</c>).
    /// </summary>
    internal static string? ExtractJsonObject(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var fence = JsonFenceRegex().Match(text);
        if (fence.Success)
        {
            return fence.Groups[1].Value.Trim();
        }

        var start = text.IndexOf('{');
        var end = text.LastIndexOf('}');
        return start >= 0 && end > start ? text[start..(end + 1)] : null;
    }

    [System.Text.RegularExpressions.GeneratedRegex(
        @"```(?:json)?\s*\n?(.*?)\s*\n?```",
        System.Text.RegularExpressions.RegexOptions.Singleline)]
    private static partial System.Text.RegularExpressions.Regex JsonFenceRegex();

    private sealed class ResponseDto
    {
        public string? Status { get; set; }
        public double? Confidence { get; set; }
        public List<IocDto>? Iocs { get; set; }

        [JsonPropertyName("phishing_indicators")]
        public List<string>? PhishingIndicators { get; set; }

        public string? Summary { get; set; }
    }

    private sealed class IocDto
    {
        public string? Type { get; set; }
        public string? Value { get; set; }
    }
}
