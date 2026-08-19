using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vigil.Core.Messaging;
using Vigil.Core.Ml;
using Vigil.Infrastructure.Messaging;
using Vigil.Infrastructure.Ml;
using Vigil.Infrastructure.Persistence;

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

    private static string ResolvePath(string path, string contentRootPath) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(path, contentRootPath);
}
