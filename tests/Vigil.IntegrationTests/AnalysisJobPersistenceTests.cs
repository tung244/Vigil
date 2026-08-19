using Microsoft.EntityFrameworkCore;
using Vigil.Core.Domain;
using Vigil.Infrastructure.Persistence;
using Xunit;

// EF1002: dbName is built from Guid.NewGuid() ("N" format = hex only), so the
// interpolated CREATE/DROP DATABASE identifiers cannot contain hostile SQL.
#pragma warning disable EF1002

namespace Vigil.IntegrationTests;

/// <summary>
/// Spins up a throwaway database per run (migrations applied from scratch),
/// round-trips an AnalysisJob, then drops the database.
/// Requires the local docker-compose Postgres on port 55432.
/// </summary>
public class AnalysisJobPersistenceTests
{
    private const string ServerConnection =
        "Host=localhost;Port=55432;Database=postgres;Username=vigil;Password=vigil_dev_password";

    [Fact]
    public async Task AnalysisJob_round_trips_through_postgres()
    {
        var dbName = $"vigil_test_{Guid.NewGuid():N}";
        var cs = ServerConnection.Replace("Database=postgres", $"Database={dbName}");

        var serverOptions = new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(ServerConnection, npg => npg.UseVector()).Options;

        await using (var server = new VigilDbContext(serverOptions))
        {
            await server.Database.ExecuteSqlRawAsync($"CREATE DATABASE {dbName}");
        }

        var options = new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(cs, npg => npg.UseVector()).Options;

        try
        {
            await using (var db = new VigilDbContext(options))
            {
                await db.Database.MigrateAsync();

                var job = new AnalysisJob
                {
                    Id = Guid.NewGuid(),
                    FileName = "email.eml",
                    FileType = ArtifactType.Eml,
                    StoragePath = "uploads/email.eml"
                };
                db.AnalysisJobs.Add(job);
                await db.SaveChangesAsync();
            }

            await using (var db = new VigilDbContext(options))
            {
                var loaded = await db.AnalysisJobs.SingleAsync();
                Assert.Equal("email.eml", loaded.FileName);
                Assert.Equal(ArtifactType.Eml, loaded.FileType);
                Assert.Equal(JobStatus.Queued, loaded.Status);
                Assert.Null(loaded.FinishedAt);
            }
        }
        finally
        {
            await using var server = new VigilDbContext(serverOptions);
            await server.Database.ExecuteSqlRawAsync(
                $"DROP DATABASE IF EXISTS {dbName} WITH (FORCE)");
        }
    }
}
