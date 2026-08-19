using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Vigil.Core.Messaging;
using Vigil.Infrastructure.Messaging;
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
}
