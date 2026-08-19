using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
}
