using System.Text;
using System.Text.Json;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Vigil.Infrastructure.Messaging;
using Vigil.Infrastructure.Tier1;

namespace Vigil.Worker;

/// <summary>
/// Consumes job messages from the durable <c>vigil.jobs</c> queue and runs the
/// Tier 1 pipeline for each. Acking policy:
/// <list type="bullet">
/// <item>Processed (or marked Failed) jobs are acked — no infinite retry.</item>
/// <item>Unparseable messages are nacked without requeue (poison messages).</item>
/// <item>Infrastructure failures (e.g. database unreachable) are nacked with
/// requeue so the job is not lost.</item>
/// </list>
/// </summary>
public sealed class JobConsumerService(
    IConfiguration configuration,
    IServiceScopeFactory scopeFactory,
    ILogger<JobConsumerService> logger) : BackgroundService
{
    private const int MaxConnectAttempts = 10;
    private static readonly TimeSpan ConnectRetryDelay = TimeSpan.FromSeconds(3);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var connectionString = configuration.GetConnectionString("RabbitMq")
            ?? throw new InvalidOperationException("Connection string 'RabbitMq' is missing.");

        await using var connection = await ConnectWithRetryAsync(connectionString, stoppingToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: stoppingToken);

        await channel.QueueDeclareAsync(
            queue: RabbitMqJobQueue.QueueName,
            durable: true,
            exclusive: false,
            autoDelete: false,
            cancellationToken: stoppingToken);
        await channel.BasicQosAsync(prefetchSize: 0, prefetchCount: 1, global: false,
            cancellationToken: stoppingToken);

        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.ReceivedAsync += async (_, args) =>
        {
            Guid jobId;
            try
            {
                jobId = ParseJobId(args.Body);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Discarding unparseable message {DeliveryTag}", args.DeliveryTag);
                await channel.BasicNackAsync(args.DeliveryTag, multiple: false, requeue: false);
                return;
            }

            try
            {
                using var scope = scopeFactory.CreateScope();
                var pipeline = scope.ServiceProvider.GetRequiredService<Tier1Pipeline>();
                var outcome = await pipeline.ProcessAsync(jobId, stoppingToken);
                logger.LogInformation("Job {JobId} processed: {Outcome}", jobId, outcome);
                await channel.BasicAckAsync(args.DeliveryTag, multiple: false);
            }
            catch (Exception ex)
            {
                // The job row could not be updated (e.g. database down): requeue
                // so the message survives and the job can be retried later.
                logger.LogError(ex, "Job {JobId} processing blew up; requeueing message", jobId);
                await channel.BasicNackAsync(args.DeliveryTag, multiple: false, requeue: true);
            }
        };

        await channel.BasicConsumeAsync(
            queue: RabbitMqJobQueue.QueueName,
            autoAck: false,
            consumer: consumer,
            cancellationToken: stoppingToken);

        logger.LogInformation("Consuming queue {Queue}", RabbitMqJobQueue.QueueName);

        try
        {
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Graceful shutdown.
        }
    }

    private async Task<IConnection> ConnectWithRetryAsync(
        string connectionString, CancellationToken stoppingToken)
    {
        var factory = new ConnectionFactory { Uri = new Uri(connectionString) };

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var connection = await factory.CreateConnectionAsync(stoppingToken);
                logger.LogInformation("Connected to RabbitMQ");
                return connection;
            }
            catch (Exception ex) when (attempt < MaxConnectAttempts)
            {
                logger.LogWarning(ex,
                    "RabbitMQ connect attempt {Attempt}/{Max} failed; retrying in {Delay}s",
                    attempt, MaxConnectAttempts, ConnectRetryDelay.TotalSeconds);
                await Task.Delay(ConnectRetryDelay, stoppingToken);
            }
        }
    }

    private static Guid ParseJobId(ReadOnlyMemory<byte> body)
    {
        using var document = JsonDocument.Parse(body);
        var raw = document.RootElement.GetProperty("jobId").GetString()
            ?? throw new FormatException("Message property 'jobId' is null.");
        return Guid.Parse(raw);
    }
}
