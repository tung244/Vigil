namespace Vigil.Infrastructure.Llm;

/// <summary>The pipeline needs an LLM but none is configured (missing Llm:ApiKey).</summary>
public sealed class LlmNotConfiguredException(string message) : Exception(message);

/// <summary>The LLM response could not be parsed into the required JSON contract after a retry.</summary>
public sealed class LlmResponseFormatException(string message) : Exception(message);
