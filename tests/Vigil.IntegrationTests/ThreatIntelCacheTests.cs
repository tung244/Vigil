using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Core.ThreatIntel;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.ThreatIntel;

namespace Vigil.IntegrationTests;

/// <summary>
/// DB-backed cache behaviour of <see cref="ThreatIntelService"/> against the
/// real Postgres container (docker-compose, Step 1). Clients run on a stub
/// HTTP handler, so no external API is ever contacted.
/// </summary>
public class ThreatIntelCacheTests : IClassFixture<VigilApiFactory>, IAsyncLifetime
{
    private readonly VigilApiFactory _factory;
    private readonly List<Guid> _createdJobIds = [];

    public ThreatIntelCacheTests(VigilApiFactory factory) => _factory = factory;

    public Task InitializeAsync() => _factory.InitializeDatabaseAsync();

    public async Task DisposeAsync()
    {
        await using var db = CreateDbContext();
        db.AnalysisJobs.RemoveRange(db.AnalysisJobs.Where(j => _createdJobIds.Contains(j.Id)));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task Second_lookup_of_same_ioc_does_not_write_new_rows_or_call_api()
    {
        var jobId = await CreateJobAsync("first.eml");
        var vtHandler = new StubHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)429));
        var abuseHandler = new StubHttpMessageHandler(_ => new HttpResponseMessage((HttpStatusCode)429));

        await using (var db = CreateDbContext())
        {
            var service = CreateService(db, vtHandler, abuseHandler);
            var results = await service.LookupAsync(IocType.Ip, "185.220.101.1", jobId);

            Assert.Equal(2, results.Count);
            Assert.All(results, r =>
            {
                Assert.False(r.FromLiveApi);
                Assert.Contains("\"fallback\":true", r.RawResponse);
            });
        }

        Assert.Equal(2, vtHandler.CallCount + abuseHandler.CallCount);

        // Second lookup — different job, same IOC — must be a pure cache hit.
        var otherJobId = await CreateJobAsync("second.eml");
        await using (var db = CreateDbContext())
        {
            var service = CreateService(db, vtHandler, abuseHandler);
            var results = await service.LookupAsync(IocType.Ip, "185.220.101.1", otherJobId);

            Assert.Equal(2, results.Count);
            Assert.All(results, r => Assert.False(r.FromLiveApi));
        }

        Assert.Equal(2, vtHandler.CallCount + abuseHandler.CallCount); // unchanged
        await using (var db = CreateDbContext())
        {
            Assert.Equal(2, await db.ThreatIntelResults
                .CountAsync(r => r.Ioc.Value == "185.220.101.1"));
        }
    }

    [Fact]
    public async Task Live_result_is_cached_with_from_live_api_flag_preserved()
    {
        var jobId = await CreateJobAsync("live.eml");
        var vtHandler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""
                {"data":{"attributes":{"last_analysis_stats":{
                    "malicious":30,"suspicious":0,"harmless":60,"undetected":0}}}}
                """)
        });
        var abuseHandler = new StubHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"data":{"abuseConfidenceScore":65}}""")
        });

        await using (var db = CreateDbContext())
        {
            var service = CreateService(db, vtHandler, abuseHandler);
            await service.LookupAsync(IocType.Ip, "198.51.100.23", jobId);
        }

        // New service instance, new context — must come from the DB cache.
        await using (var db = CreateDbContext())
        {
            var service = CreateService(db, vtHandler, abuseHandler);
            var results = await service.LookupAsync(IocType.Ip, "198.51.100.23", jobId);

            Assert.Equal(2, results.Count);
            var vt = results.Single(r => r.Source == ThreatIntelSource.VirusTotal);
            var abuse = results.Single(r => r.Source == ThreatIntelSource.AbuseIpDb);
            Assert.True(vt.FromLiveApi);
            Assert.True(abuse.FromLiveApi);
            Assert.Equal(30.0 / 90.0, vt.MaliciousScore, precision: 6);
            Assert.Equal(0.65, abuse.MaliciousScore, precision: 6);
        }

        Assert.Equal(2, vtHandler.CallCount + abuseHandler.CallCount); // only the first pass
    }

    private static ThreatIntelService CreateService(
        VigilDbContext db, StubHttpMessageHandler vtHandler, StubHttpMessageHandler abuseHandler)
    {
        // Keys are set on purpose: any cache miss would show up as an HTTP
        // call on the stub handlers, which the assertions count.
        var options = new ThreatIntelOptions
        {
            VirusTotalApiKey = "vt-key",
            AbuseIpDbApiKey = "abuse-key",
            CacheHours = 24
        };
        return new ThreatIntelService(
            db,
            new VirusTotalClient(new HttpClient(vtHandler), options,
                NullLogger<VirusTotalClient>.Instance),
            new AbuseIpDbClient(new HttpClient(abuseHandler), options,
                NullLogger<AbuseIpDbClient>.Instance),
            options,
            NullLogger<ThreatIntelService>.Instance);
    }

    private async Task<Guid> CreateJobAsync(string fileName)
    {
        await using var db = CreateDbContext();
        var job = new AnalysisJob
        {
            Id = Guid.NewGuid(),
            FileName = fileName,
            FileType = ArtifactType.Eml,
            StoragePath = $"/tmp/{fileName}"
        };
        db.AnalysisJobs.Add(job);
        await db.SaveChangesAsync();
        _createdJobIds.Add(job.Id);
        return job.Id;
    }

    private static VigilDbContext CreateDbContext() =>
        new(new DbContextOptionsBuilder<VigilDbContext>()
            .UseNpgsql(VigilApiFactory.PostgresConnection, npg => npg.UseVector())
            .Options);

    /// <summary>Scripted HTTP stub: counts calls, replies via the delegate.</summary>
    private sealed class StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        public int CallCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(responder(request));
        }
    }
}
