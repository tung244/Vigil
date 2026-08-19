using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;
using Vigil.Core.Tier2;
using Vigil.Infrastructure.Llm;

namespace Vigil.Infrastructure.Tier2;

/// <summary>
/// Tier 2 Email Analyst stage. Unlike the old LangGraph ReAct loop (LLM
/// decides which tool to call next, up to 12 steps), the deterministic design
/// pre-computes the tool output, sends one prompt and asks for the final JSON
/// — the LLM may still invoke EmailTools functions via auto function calling,
/// but it never routes anywhere. The response is parsed strictly; a malformed
/// answer gets exactly one retry with a corrective instruction, then throws
/// <see cref="LlmResponseFormatException"/>.
/// </summary>
public sealed class EmailAnalystStage(LlmKernelProvider llm, ILogger<EmailAnalystStage> logger)
{
    private const int MaxAttempts = 2;

    public async Task<EmailAnalysisResult> AnalyzeAsync(
        string scrubbedPayload,
        IReadOnlyCollection<string> matchedRules,
        CancellationToken cancellationToken = default)
    {
        var kernel = llm.Kernel
            ?? throw new LlmNotConfiguredException(
                "LLM not configured: set Llm:ApiKey (provider gemini) to enable the email analyst stage.");
        var chat = kernel.Services.GetRequiredService<IChatCompletionService>();

        var toolOutputJson = new EmailTools().BuildToolOutputJson(scrubbedPayload);

        var history = new ChatHistory(EmailAnalystPrompts.SystemPrompt);
        history.AddUserMessage(EmailAnalystPrompts.BuildUserPrompt(scrubbedPayload, matchedRules, toolOutputJson));

        // In-step tool calling only: the LLM can invoke EmailTools functions,
        // but the deterministic state machine owns stage-to-stage routing.
        var settings = new PromptExecutionSettings { FunctionChoiceBehavior = FunctionChoiceBehavior.Auto() };

        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            var messages = await chat.GetChatMessageContentsAsync(history, settings, kernel, cancellationToken);
            var text = messages.LastOrDefault()?.Content;

            if (EmailAnalysisResponseParser.TryParse(text, out var result))
            {
                logger.LogInformation(
                    "Email analyst verdict: {Status} (confidence {Confidence:F2}, {IocCount} IOCs, attempt {Attempt})",
                    result!.Status, result.Confidence, result.Iocs.Count, attempt);
                return result;
            }

            logger.LogWarning("Email analyst response malformed (attempt {Attempt}/{Max})", attempt, MaxAttempts);
            if (attempt < MaxAttempts)
            {
                history.AddAssistantMessage(text ?? string.Empty);
                history.AddUserMessage(EmailAnalystPrompts.RetryInstruction);
            }
        }

        throw new LlmResponseFormatException(
            $"Email analyst LLM response did not match the JSON contract after {MaxAttempts} attempts.");
    }
}
