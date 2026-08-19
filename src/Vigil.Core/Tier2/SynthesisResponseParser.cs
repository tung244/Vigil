using System.Text.Json;
using System.Text.Json.Serialization;
using Vigil.Core.Domain;

namespace Vigil.Core.Tier2;

/// <summary>
/// Strict parser for the Synthesis LLM response. Same strategy as
/// <see cref="EmailAnalysisResponseParser"/>: accepts the bare JSON object or
/// one wrapped in a markdown fence, rejects everything else. Shape checks only
/// (valid JSON, numeric risk score, known severity, non-empty summary) — the
/// semantic contract (severity band, MITRE format, evidence trail) is enforced
/// separately by <see cref="ReportValidator"/>.
/// </summary>
public static class SynthesisResponseParser
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    public static bool TryParse(string? rawResponse, out SynthesisResult? result)
    {
        result = null;
        var json = EmailAnalysisResponseParser.ExtractJsonObject(rawResponse);
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
            || dto.RiskScore is null
            || !Enum.TryParse<Severity>(dto.Severity, ignoreCase: true, out var severity)
            || string.IsNullOrWhiteSpace(dto.SummaryMarkdown))
        {
            return false;
        }

        result = new SynthesisResult
        {
            RiskScore = dto.RiskScore.Value,
            Severity = severity,
            SummaryMarkdown = dto.SummaryMarkdown.Trim(),
            MitreTechniques = (dto.MitreTechniques ?? [])
                .Where(t => !string.IsNullOrWhiteSpace(t))
                .Select(t => t.Trim())
                .ToList(),
            RecommendedActions = (dto.RecommendedActions ?? [])
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.Trim())
                .ToList(),
            EvidenceTrail = (dto.EvidenceTrail ?? [])
                .Where(e => !string.IsNullOrWhiteSpace(e.Claim) && !string.IsNullOrWhiteSpace(e.Source))
                .Select(e => new EvidenceItem(e.Claim!.Trim(), e.Source!.Trim()))
                .ToList()
        };
        return true;
    }

    private sealed class ResponseDto
    {
        [JsonPropertyName("risk_score")]
        public double? RiskScore { get; set; }

        public string? Severity { get; set; }

        [JsonPropertyName("summary_markdown")]
        public string? SummaryMarkdown { get; set; }

        [JsonPropertyName("mitre_techniques")]
        public List<string>? MitreTechniques { get; set; }

        [JsonPropertyName("recommended_actions")]
        public List<string>? RecommendedActions { get; set; }

        [JsonPropertyName("evidence_trail")]
        public List<EvidenceDto>? EvidenceTrail { get; set; }
    }

    private sealed class EvidenceDto
    {
        public string? Claim { get; set; }
        public string? Source { get; set; }
    }
}
