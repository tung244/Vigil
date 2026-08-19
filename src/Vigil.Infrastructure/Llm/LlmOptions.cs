namespace Vigil.Infrastructure.Llm;

/// <summary>
/// LLM configuration, bound manually from the "Llm" config section:
/// Provider (default "gemini"), ApiKey (empty = LLM disabled, worker still
/// starts), Model (default "gemini-2.5-flash").
/// </summary>
public sealed class LlmOptions
{
    public string Provider { get; init; } = "gemini";
    public string ApiKey { get; init; } = string.Empty;
    public string Model { get; init; } = "gemini-2.5-flash";

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(ApiKey)
        && string.Equals(Provider, "gemini", StringComparison.OrdinalIgnoreCase);
}
