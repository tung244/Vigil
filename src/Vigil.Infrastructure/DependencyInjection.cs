using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Polly;
using Vigil.Core.Messaging;
using Vigil.Core.Ml;
using Vigil.Core.ThreatIntel;
using Vigil.Infrastructure.Llm;
using Vigil.Infrastructure.Messaging;
using Vigil.Infrastructure.Ml;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.ThreatIntel;
using Vigil.Infrastructure.Tier2;

namespace Vigil.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddVigilPersistence(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<VigilDbContext>(options =>
            options.UseNpgsql(
                configuration.GetConnectionString("Postgres"),
                npgsql => npgsql.UseVector()));

        return services;
    }

    public static IServiceCollection AddVigilMessaging(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IJobQueue>(sp =>
            new RabbitMqJobQueue(
                configuration.GetConnectionString("RabbitMq")
                    ?? throw new InvalidOperationException("Connection string 'RabbitMq' is missing."),
                sp.GetRequiredService<ILogger<RabbitMqJobQueue>>()));

        return services;
    }

    /// <summary>
    /// Registers the ONNX phishing classifier as a lazy-loaded singleton.
    /// Config section "Ml": Enabled (default true), Threshold (default 0.7),
    /// ModelPath (default "models/phishing.onnx"), VocabPath (default
    /// "models/vocab.txt"); relative paths resolve against the content root.
    /// </summary>
    public static IServiceCollection AddVigilMachineLearning(
        this IServiceCollection services, IConfiguration configuration, string contentRootPath)
    {
        services.AddSingleton<IPhishingClassifier>(sp =>
        {
            // Manual parsing keeps Microsoft.Extensions.Configuration.Binder out
            // of the dependency list for two scalar settings.
            var enabled = !bool.TryParse(configuration["Ml:Enabled"], out var e) || e;
            var threshold = double.TryParse(
                configuration["Ml:Threshold"], CultureInfo.InvariantCulture, out var t) ? t : 0.7;
            var modelPath = ResolvePath(
                configuration["Ml:ModelPath"] ?? "models/phishing.onnx", contentRootPath);
            var vocabPath = ResolvePath(
                configuration["Ml:VocabPath"] ?? "models/vocab.txt", contentRootPath);

            return new PhishingClassifier(
                modelPath, vocabPath, threshold, enabled,
                sp.GetRequiredService<ILogger<PhishingClassifier>>());
        });

        return services;
    }

    /// <summary>
    /// Registers the threat intel clients (VirusTotal v3, AbuseIPDB v2) with a
    /// 10s timeout and 2 retries on transient HTTP errors, plus the cache-first
    /// <see cref="IThreatIntelService"/>. Config section "ThreatIntel":
    /// VirusTotalApiKey, AbuseIpDbApiKey (empty = heuristic fallback),
    /// CacheHours (default 24).
    /// </summary>
    public static IServiceCollection AddVigilThreatIntel(
        this IServiceCollection services, IConfiguration configuration)
    {
        var options = new ThreatIntelOptions
        {
            VirusTotalApiKey = configuration["ThreatIntel:VirusTotalApiKey"] ?? "",
            AbuseIpDbApiKey = configuration["ThreatIntel:AbuseIpDbApiKey"] ?? "",
            CacheHours = int.TryParse(
                configuration["ThreatIntel:CacheHours"], CultureInfo.InvariantCulture, out var h) && h > 0
                ? h
                : 24
        };
        services.AddSingleton(options);

        services.AddHttpClient<VirusTotalClient>(client => client.Timeout = TimeSpan.FromSeconds(10))
            .AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(
                2, attempt => TimeSpan.FromMilliseconds(250 * attempt)));

        services.AddHttpClient<AbuseIpDbClient>(client => client.Timeout = TimeSpan.FromSeconds(10))
            .AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(
                2, attempt => TimeSpan.FromMilliseconds(250 * attempt)));

        services.AddScoped<IThreatIntelService, ThreatIntelService>();

        return services;
    }

    /// <summary>
    /// Registers the LLM stack: <see cref="LlmOptions"/> from the "Llm" config
    /// section (Provider default "gemini", ApiKey default empty, Model default
    /// "gemini-2.5-flash"), the singleton <see cref="LlmKernelProvider"/> (null
    /// kernel when no key — the worker starts anyway) and the scoped Tier 2
    /// pipeline with its stages.
    /// </summary>
    public static IServiceCollection AddVigilLlm(
        this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton(new LlmOptions
        {
            Provider = configuration["Llm:Provider"] ?? "gemini",
            ApiKey = configuration["Llm:ApiKey"] ?? "",
            Model = configuration["Llm:Model"] ?? "gemini-2.5-flash"
        });
        services.AddSingleton<LlmKernelProvider>();

        services.AddScoped<EmailAnalystStage>();
        services.AddScoped<ThreatIntelStage>();
        services.AddScoped<Tier2Pipeline>();

        return services;
    }

    private static string ResolvePath(string path, string contentRootPath) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(path, contentRootPath);
}
