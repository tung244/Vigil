using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace Vigil.IntegrationTests;

/// <summary>
/// Món 1 (OWASP hardening): auth, security headers, upload content sniffing.
/// Requires docker-compose services running (the factory boots the real API).
/// </summary>
public class ApiSecurityTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private readonly VigilApiFactory _factory;

    public ApiSecurityTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData("/api/jobs")]
    [InlineData("/api/stats")]
    [InlineData("/api/stats/mitre")]
    public async Task Protected_endpoints_reject_anonymous_requests(string path)
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Health_stays_anonymous()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Login_with_wrong_password_returns_401()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/login",
            new { username = VigilApiFactory.TestUsername, password = "wrong" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Login_then_call_protected_endpoint_with_token()
    {
        // CreateAuthenticatedClientAsync itself logs in through the endpoint.
        var client = await _factory.CreateAuthenticatedClientAsync();

        var response = await client.GetAsync("/api/stats");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Upload_with_executable_content_returns_400()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        // MZ header + NUL bytes — a PE executable renamed to .eml.
        var payload = new byte[] { (byte)'M', (byte)'Z', 0x90, 0x00, 0x03, 0x00 };
        using var content = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent(payload);
        content.Add(fileContent, "file", "definitely-not-malware.eml");

        var response = await client.PostAsync("/api/jobs", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_json_extension_with_non_json_content_returns_400()
    {
        var client = await _factory.CreateAuthenticatedClientAsync();

        using var content = new MultipartFormDataContent();
        using var fileContent = new ByteArrayContent("just some prose, not json"u8.ToArray());
        content.Add(fileContent, "file", "cloudtrail.json");

        var response = await client.PostAsync("/api/jobs", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Responses_carry_security_headers()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.True(response.Headers.Contains("Content-Security-Policy"));
    }
}
