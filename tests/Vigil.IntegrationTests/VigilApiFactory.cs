using System.Net.Http.Headers;
using System.Net.Http.Json;
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
/// Auth is real (JWT) — use <see cref="CreateAuthenticatedClientAsync"/>;
/// rate limits are raised so the suite never trips them.
/// </summary>
public class VigilApiFactory : WebApplicationFactory<Program>
{
    public const string TestUsername = "test-admin";
    public const string TestPassword = "test-password-not-a-real-secret";

    // Env-overridable via VIGIL_TEST_POSTGRES / VIGIL_TEST_RABBITMQ (see TestConnections).
    public static string PostgresConnection => TestConnections.Postgres;

    public static string RabbitMqConnection => TestConnections.RabbitMq;

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
                ["ConnectionStrings:RabbitMq"] = RabbitMqConnection,
                ["Storage:UploadDir"] = UploadDir,
                ["Auth:SigningKey"] = "integration-test-signing-key-0123456789abcdef",
                ["Auth:AdminUser"] = TestUsername,
                ["Auth:AdminPassword"] = TestPassword,
                // The suite fires many requests per factory instance.
                ["RateLimiting:UploadPermitLimit"] = "100000",
                ["RateLimiting:AuthPermitLimit"] = "100000"
            });
        });
    }

    /// <summary>Client with a real JWT obtained through the login endpoint.</summary>
    public async Task<HttpClient> CreateAuthenticatedClientAsync()
    {
        var client = CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login",
            new { username = TestUsername, password = TestPassword });
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<LoginTestDto>();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", body!.Token);
        return client;
    }

    public async Task InitializeDatabaseAsync()
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VigilDbContext>();
        await db.Database.MigrateAsync();
    }

    private sealed record LoginTestDto(string Token, int ExpiresInMinutes);
}
