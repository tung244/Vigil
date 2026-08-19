using Microsoft.Extensions.Logging;
using Microsoft.SemanticKernel;

namespace Vigil.Infrastructure.Llm;

/// <summary>
/// Holds the Semantic Kernel instance for the worker. When the "Llm" config
/// section has no API key (or an unsupported provider) the kernel is null and
/// <see cref="IsConfigured"/> is false: the worker still starts and runs Tier
/// 1 + the deterministic Tier 2 stages, but any stage needing the LLM fails
/// the job with a clear error instead of crashing the host. Tests inject a
/// kernel backed by a fake IChatCompletionService via the kernel-only ctor.
/// </summary>
public sealed class LlmKernelProvider
{
    public LlmOptions Options { get; }
    public Kernel? Kernel { get; }
    public bool IsConfigured => Kernel is not null;

    public LlmKernelProvider(LlmOptions options, ILogger<LlmKernelProvider> logger)
    {
        Options = options;
        if (options.IsConfigured)
        {
            logger.LogInformation("LLM configured: provider={Provider}, model={Model}", options.Provider, options.Model);
            Kernel = BuildKernel(options);
        }
        else
        {
            logger.LogWarning(
                "LLM not configured (Llm:ApiKey empty or unsupported provider '{Provider}'); " +
                "LLM-dependent Tier 2 stages will mark jobs Failed.", options.Provider);
            Kernel = null;
        }
    }

    /// <summary>Test seam: wrap a caller-built kernel (e.g. with a fake chat service).</summary>
    public LlmKernelProvider(Kernel kernel)
    {
        Options = new LlmOptions { ApiKey = "test-double" };
        Kernel = kernel;
    }

    private static Kernel BuildKernel(LlmOptions options)
    {
        var builder = Kernel.CreateBuilder();
#pragma warning disable SKEXP0070 // Google Gemini connector is alpha; no GA alternative exists
        builder.AddGoogleAIGeminiChatCompletion(modelId: options.Model, apiKey: options.ApiKey);
#pragma warning restore SKEXP0070
        builder.Plugins.AddFromObject(new EmailTools(), "EmailTools");
        return builder.Build();
    }
}
