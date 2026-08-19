using Microsoft.SemanticKernel;
using Microsoft.SemanticKernel.ChatCompletion;

namespace Vigil.IntegrationTests.Llm;

/// <summary>
/// Deterministic stand-in for the Gemini chat completion service: returns
/// queued responses verbatim, records every call. Registered into the SK
/// kernel's service collection in place of the real connector, so the Tier 2
/// pipeline runs end-to-end without an API key or any network call.
/// </summary>
public sealed class FakeChatCompletionService : IChatCompletionService
{
    private readonly Queue<string> _responses;

    public FakeChatCompletionService(params string[] responses) =>
        _responses = new Queue<string>(responses);

    public int CallCount { get; private set; }

    /// <summary>User-message texts the pipeline sent, one entry per call.</summary>
    public List<string?> ReceivedLastUserMessages { get; } = [];

    public IReadOnlyDictionary<string, object?> Attributes { get; } =
        new Dictionary<string, object?>();

    public Task<IReadOnlyList<ChatMessageContent>> GetChatMessageContentsAsync(
        ChatHistory chatHistory,
        PromptExecutionSettings? executionSettings = null,
        Kernel? kernel = null,
        CancellationToken cancellationToken = default)
    {
        CallCount++;
        ReceivedLastUserMessages.Add(chatHistory.LastOrDefault(m => m.Role == AuthorRole.User)?.Content);

        if (_responses.Count == 0)
        {
            throw new InvalidOperationException(
                "Fake chat service was called but has no queued response — the pipeline should not have invoked the LLM.");
        }

        var text = _responses.Dequeue();
        IReadOnlyList<ChatMessageContent> messages = [new ChatMessageContent(AuthorRole.Assistant, text)];
        return Task.FromResult(messages);
    }

    public IAsyncEnumerable<StreamingChatMessageContent> GetStreamingChatMessageContentsAsync(
        ChatHistory chatHistory,
        PromptExecutionSettings? executionSettings = null,
        Kernel? kernel = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Streaming is not used by the pipeline.");
}
