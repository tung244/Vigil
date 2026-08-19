namespace Vigil.UnitTests.ThreatIntel;

/// <summary>
/// Scripted HttpMessageHandler: records each request and replies (or throws)
/// via the supplied delegate. Used to exercise the threat intel clients
/// without any network access.
/// </summary>
internal sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
    : HttpMessageHandler
{
    public int CallCount { get; private set; }
    public HttpRequestMessage? LastRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        CallCount++;
        LastRequest = request;
        return Task.FromResult(responder(request));
    }
}
