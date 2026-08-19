using System.ComponentModel;
using System.Text.Json;
using Microsoft.SemanticKernel;
using Vigil.Core.Tier1;
using Vigil.Core.Tier2;

namespace Vigil.Infrastructure.Llm;

/// <summary>
/// Semantic Kernel plugin for the Email Analyst stage, ported from the old
/// <c>email_analyst/tools.py</c>. The deterministic pipeline also calls these
/// directly to pre-compute tool output for the prompt; the LLM may invoke
/// them again via auto function calling. The vector similarity search tool of
/// the old system is intentionally absent — RAG lands in Step 9.
/// </summary>
public sealed class EmailTools
{
    private const int MaxBodyChars = 2000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    [KernelFunction("parse_eml")]
    [Description("Parse raw .eml content into headers, body text, sender, subject, received chain and header IPs.")]
    public string ParseEml([Description("Raw .eml text")] string emlContent)
    {
        var message = EmlParser.Parse(emlContent);
        var headerIps = message.GetHeaders("Received")
            .Concat(message.GetHeaders("X-Originating-IP"))
            .SelectMany(h => NetworkEntityExtractor.Extract(h).Ips)
            .Distinct()
            .ToList();

        var body = message.Body;
        if (body.Length > MaxBodyChars)
        {
            body = body[..MaxBodyChars] + "\n[... truncated ...]";
        }

        return JsonSerializer.Serialize(new
        {
            sender = message.From,
            subject = message.Subject,
            bodyText = body,
            receivedChain = message.GetHeaders("Received").ToList(),
            headerIps,
            metadata = new
            {
                messageId = message.GetHeader("Message-ID"),
                date = message.GetHeader("Date"),
                contentType = message.GetHeader("Content-Type"),
                authenticationResults = message.GetHeader("Authentication-Results")
            }
        }, JsonOptions);
    }

    [KernelFunction("extract_network_entities")]
    [Description("Extract all URLs, domains and IP addresses from text.")]
    public string ExtractNetworkEntities([Description("Text to scan")] string text)
    {
        var entities = NetworkEntityExtractor.Extract(text);
        return JsonSerializer.Serialize(new
        {
            urls = entities.Urls,
            domains = entities.Domains,
            ips = entities.Ips
        }, JsonOptions);
    }

    /// <summary>Pre-computed tool output embedded in the analyst prompt.</summary>
    public string BuildToolOutputJson(string scrubbedPayload) =>
        $$"""{"parse_eml": {{ParseEml(scrubbedPayload)}}, "extract_network_entities": {{ExtractNetworkEntities(scrubbedPayload)}}}""";
}
