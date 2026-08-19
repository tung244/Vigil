using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Vigil.Infrastructure.Persistence;

/// <summary>
/// Design-time factory so `dotnet ef` can run against Infrastructure directly,
/// without needing the API startup project.
/// Override the default local connection via the VIGIL_POSTGRES env var.
/// </summary>
public class VigilDbContextFactory : IDesignTimeDbContextFactory<VigilDbContext>
{
    public VigilDbContext CreateDbContext(string[] args)
    {
        var connectionString =
            Environment.GetEnvironmentVariable("VIGIL_POSTGRES")
            ?? "Host=localhost;Port=55432;Database=vigil;Username=vigil;Password=vigil_dev_password";

        var options = new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(connectionString, npgsql => npgsql.UseVector())
            .Options;

        return new VigilDbContext(options);
    }
}
