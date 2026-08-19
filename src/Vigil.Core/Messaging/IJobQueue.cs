namespace Vigil.Core.Messaging;

/// <summary>
/// Abstraction over the job queue so the API never touches RabbitMQ directly.
/// The Worker consumes these messages; a job must survive a worker crash.
/// </summary>
public interface IJobQueue
{
    Task PublishJobAsync(Guid jobId, CancellationToken cancellationToken = default);
}
