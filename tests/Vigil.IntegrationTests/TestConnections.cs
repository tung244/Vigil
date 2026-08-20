using Npgsql;

namespace Vigil.IntegrationTests;

/// <summary>
/// Connection strings for the integration tests. The defaults match the local
/// docker-compose stack (Postgres on host port 55432, RabbitMQ on 5672); CI
/// and other environments override them via the VIGIL_TEST_POSTGRES and
/// VIGIL_TEST_RABBITMQ environment variables.
/// </summary>
public static class TestConnections
{
    public static string Postgres =>
        Environment.GetEnvironmentVariable("VIGIL_TEST_POSTGRES")
        ?? "Host=localhost;Port=55432;Database=vigil_api_test;Username=vigil;Password=vigil_dev_password";

    /// <summary>
    /// Same server as <see cref="Postgres"/>, but connected to the built-in
    /// maintenance database — used by tests that create/drop throwaway
    /// databases per run.
    /// </summary>
    public static string PostgresServer =>
        new NpgsqlConnectionStringBuilder(Postgres) { Database = "postgres" }.ConnectionString;

    public static string RabbitMq =>
        Environment.GetEnvironmentVariable("VIGIL_TEST_RABBITMQ")
        ?? "amqp://vigil:vigil_dev_password@localhost:5672/";
}
