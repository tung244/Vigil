using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RabbitMQ.Client;
using Vigil.Core.Messaging;

namespace Vigil.Infrastructure.Messaging;

/// <summary>
/// Publishes job messages to a durable RabbitMQ queue.
/// A single lazily-opened connection is reused; channel creation is serialized.
/// </summary>
public sealed class RabbitMqJobQueue : IJobQueue, IAsyncDisposable
{
    public const string QueueName = "vigil.jobs";

    private readonly string _connectionString;
    private readonly ILogger<RabbitMqJobQueue> _logger;
    private readonly SemaphoreSlim _initLock = new(1, 1);
    private IConnection? _connection;

    public RabbitMqJobQueue(string connectionString, ILogger<RabbitMqJobQueue> logger)
    {
        _connectionString = connectionString;
        _logger = logger;
    }

    public async Task PublishJobAsync(Guid jobId, CancellationToken cancellationToken = default)
    {
        var connection = await GetConnectionAsync(cancellationToken);
        await using var channel = await connection.CreateChannelAsync(cancellationToken: cancellationToken);

        await channel.QueueDeclareAsync(
            queue: QueueName,
            durable: true,
            exclusive: false,
            autoDelete: false,
            cancellationToken: cancellationToken);

        var body = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { jobId }));
        var properties = new BasicProperties { Persistent = true };

        await channel.BasicPublishAsync(
            exchange: string.Empty,
            routingKey: QueueName,
            mandatory: false,
            basicProperties: properties,
            body: body,
            cancellationToken: cancellationToken);

        _logger.LogInformation("Published job {JobId} to queue {Queue}", jobId, QueueName);
    }

    private async Task<IConnection> GetConnectionAsync(CancellationToken cancellationToken)
    {
        if (_connection is { IsOpen: true })
        {
            return _connection;
        }

        await _initLock.WaitAsync(cancellationToken);
        try
        {
            if (_connection is { IsOpen: true })
            {
                return _connection;
            }

            var factory = new ConnectionFactory { Uri = new Uri(_connectionString) };
            _connection = await factory.CreateConnectionAsync(cancellationToken);
            _logger.LogInformation("Connected to RabbitMQ");
            return _connection;
        }
        finally
        {
            _initLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_connection is not null)
        {
            await _connection.DisposeAsync();
        }

        _initLock.Dispose();
    }
}
