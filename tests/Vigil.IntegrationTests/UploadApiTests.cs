using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.EntityFrameworkCore;
using RabbitMQ.Client;
using Vigil.Core.Domain;
using Vigil.Infrastructure.Messaging;
using Vigil.Infrastructure.Persistence;
using Xunit;

namespace Vigil.IntegrationTests;

/// <summary>
/// End-to-end: POST /api/jobs → 202 → job row in Postgres → message in RabbitMQ.
/// Requires docker-compose services running (Step 1).
/// </summary>
public class UploadApiTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private readonly VigilApiFactory _factory;

    public UploadApiTests(VigilApiFactory factory) => _factory = factory;

    public async Task InitializeAsync()
    {
        await _factory.InitializeDatabaseAsync();

        // Start from a clean queue so BasicGet below reads this test's message.
        await using var connection = await RabbitConnectionAsync();
        await using var channel = await connection.CreateChannelAsync();
        await channel.QueueDeclareAsync(RabbitMqJobQueue.QueueName, durable: true,
            exclusive: false, autoDelete: false);
        await channel.QueuePurgeAsync(RabbitMqJobQueue.QueueName);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task Upload_eml_accepts_persists_and_queues_job()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        var fixturePath = Path.Combine(AppContext.BaseDirectory, "fixtures", "email.eml");
        await using var fileStream = File.OpenRead(fixturePath);
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(fileStream);
        content.Add(fileContent, "file", "email.eml");

        var response = await client.PostAsync("/api/jobs", content);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var accepted = await response.Content.ReadFromJsonAsync<JobAcceptedTestDto>();
        Assert.NotNull(accepted);
        Assert.NotEqual(Guid.Empty, accepted!.JobId);
        Assert.Equal($"/api/jobs/{accepted.JobId}", response.Headers.Location?.ToString());

        // GET returns the job.
        var getResponse = await client.GetAsync($"/api/jobs/{accepted.JobId}");
        getResponse.EnsureSuccessStatusCode();

        // Job row exists in Postgres with Queued status.
        var options = new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector()).Options;
        await using (var db = new VigilDbContext(options))
        {
            var job = await db.AnalysisJobs.SingleAsync(j => j.Id == accepted.JobId);
            Assert.Equal("email.eml", job.FileName);
            Assert.Equal(ArtifactType.Eml, job.FileType);
            Assert.Equal(JobStatus.Queued, job.Status);
            Assert.True(File.Exists(job.StoragePath));
        }

        // Message for this job is in the queue. The queue is shared with the
        // parallel Tier1PipelineTests uploads, so drain until our message shows
        // up (nothing else consumes it; the Worker is not running here).
        await using (var connection = await RabbitConnectionAsync())
        await using (var channel = await connection.CreateChannelAsync())
        {
            var found = false;
            for (var attempt = 0; attempt < 20 && !found; attempt++)
            {
                var message = await channel.BasicGetAsync(RabbitMqJobQueue.QueueName, autoAck: true);
                if (message is null)
                {
                    break;
                }

                found = Encoding.UTF8.GetString(message.Body.Span)
                    .Contains(accepted.JobId.ToString(), StringComparison.Ordinal);
            }

            Assert.True(found, "No RabbitMQ message carried the uploaded job id.");
        }

        // Cleanup: keep the shared test database readable between runs.
        await using (var db = new VigilDbContext(options))
        {
            db.AnalysisJobs.RemoveRange(db.AnalysisJobs.Where(j => j.Id == accepted.JobId));
            await db.SaveChangesAsync();
        }
    }

    [Fact]
    public async Task Upload_unsupported_extension_returns_400()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        using var content = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent("not an artifact"u8.ToArray());
        content.Add(fileContent, "file", "notes.txt");

        var response = await client.PostAsync("/api/jobs", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static async Task<IConnection> RabbitConnectionAsync()
    {
        var factory = new ConnectionFactory { Uri = new Uri(VigilApiFactory.RabbitMqConnection) };
        return await factory.CreateConnectionAsync();
    }

    private sealed record JobAcceptedTestDto(Guid JobId, string Status);
}
