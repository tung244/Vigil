using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Vigil.Infrastructure.Persistence;

namespace Vigil.IntegrationTests;

/// <summary>
/// API under test with a dedicated throwaway-ish database (vigil_api_test)
/// and a temp upload dir. RabbitMQ stays the real local container.
/// </summary>
public class VigilApiFactory : WebApplicationFactory<Program>
{
    public const string PostgresConnection =
        "Host=localhost;Port=55432;Database=vigil_api_test;Username=vigil;Password=vigil_dev_password";

    public const string RabbitMqConnection = "amqp://vigil:vigil_dev_password@localhost:5672/";

    public string UploadDir { get; } =
        Path.Combine(Path.GetTempPath(), $"vigil-test-uploads-{Guid.NewGuid():N}");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Postgres"] = PostgresConnection,
                ["Storage:UploadDir"] = UploadDir
            });
        });
    }

    public async Task InitializeDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VigilDbContext>();
        await db.Database.MigrateAsync();
    }
}
