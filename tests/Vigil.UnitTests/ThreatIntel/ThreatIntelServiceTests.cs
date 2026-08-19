using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Core.Domain;
using Vigil.Infrastructure.Persistence;
using Vigil.Infrastructure.ThreatIntel;

namespace Vigil.UnitTests.ThreatIntel;

/// <summary>
/// Service-level tests on EF Core InMemory: cache behaviour and the
/// live-API → heuristic-fallback degradation path.
/// </summary>
public class ThreatIntelServiceTests
{
    private readonly VigilDbContext _db;
    private readonly Guid _jobId = Guid.NewGuid();

    public ThreatIntelServiceTests()
    {
        _db = new TestDbContext(new DbContextOptionsBuilder<VigilDbContext>()
            .UseInMemoryDatabase($"threat-intel-{Guid.NewGuid():N}")
            .Options);
        _db.AnalysisJobs.Add(new AnalysisJob
        {
            Id = _jobId,
            FileName = "test.eml",
            FileType = ArtifactType.Eml,
            StoragePath = "/tmp/test.eml"
        });
        _db.SaveChanges();
    }

    private ThreatIntelService CreateService(
        Func<HttpRequestMessage, HttpResponseMessage>? vtResponder = null,
        Func<HttpRequestMessage, HttpResponseMessage>? abuseResponder = null,
        ThreatIntelOptions? options = null,
        StubHttpMessageHandler? vtHandler = null,
        StubHttpMessageHandler? abuseHandler = null)
    {
        options ??= new ThreatIntelOptions
        {
            VirusTotalApiKey = "vt-key",
            AbuseIpDbApiKey = "abuse-key",
            CacheHours = 24
        };
        var vt = new VirusTotalClient(
            new HttpClient(vtHandler ?? new StubHttpMessageHandler(
                vtResponder ?? (_ => OkVtStats(0, 0, 90, 0)))),
            options, NullLogger<VirusTotalClient>.Instance);
        var abuse = new AbuseIpDbClient(
            new HttpClient(abuseHandler ?? new StubHttpMessageHandler(
                abuseResponder ?? (_ => OkAbuse(0)))),
            options, NullLogger<AbuseIpDbClient>.Instance);
        return new ThreatIntelService(_db, vt, abuse, options,
            NullLogger<ThreatIntelService>.Instance);
    }

    private static HttpResponseMessage OkVtStats(int malicious, int suspicious, int harmless, int undetected) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                data = new
                {
                    attributes = new
                    {
                        last_analysis_stats = new { malicious, suspicious, harmless, undetected }
                    }
                }
            }))
        };

    private static HttpResponseMessage OkAbuse(int confidence) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                data = new { abuseConfidenceScore = confidence }
            }))
        };

    [Fact]
    public async Task Live_200_results_are_persisted_for_both_sources_on_ip()
    {
        var service = CreateService(
            vtResponder: _ => OkVtStats(45, 5, 40, 0),
            abuseResponder: _ => OkAbuse(80));

        var results = await service.LookupAsync(IocType.Ip, "203.0.113.7", _jobId);

        Assert.Equal(2, results.Count);
        var vt = results.Single(r => r.Source == ThreatIntelSource.VirusTotal);
        var abuse = results.Single(r => r.Source == ThreatIntelSource.AbuseIpDb);
        Assert.True(vt.FromLiveApi);
        Assert.True(abuse.FromLiveApi);
        Assert.Equal(45.0 / 90.0, vt.MaliciousScore, precision: 6);
        Assert.Equal(0.80, abuse.MaliciousScore, precision: 6);
        Assert.Equal(2, await _db.ThreatIntelResults.CountAsync());
        Assert.Equal(1, await _db.Iocs.CountAsync());
    }

    [Fact]
    public async Task Rate_limit_429_falls_back_to_heuristic_and_persists()
    {
        var service = CreateService(
            vtResponder: _ => new HttpResponseMessage((HttpStatusCode)429),
            abuseResponder: _ => new HttpResponseMessage((HttpStatusCode)429));

        var results = await service.LookupAsync(IocType.Ip, "185.220.101.1", _jobId);

        Assert.Equal(2, results.Count);
        Assert.All(results, r =>
        {
            Assert.False(r.FromLiveApi);
            Assert.Contains("\"fallback\":true", r.RawResponse);
            Assert.Contains("http_429", r.RawResponse);
        });
        // 0.40 Tor prefix + 0.15 geo heuristic
        Assert.All(results, r => Assert.Equal(0.55, r.MaliciousScore, precision: 6));
        Assert.Equal(2, await _db.ThreatIntelResults.CountAsync());
    }

    [Fact]
    public async Task Timeout_falls_back_to_heuristic_without_throwing()
    {
        var service = CreateService(
            vtResponder: _ => throw new TaskCanceledException(),
            abuseResponder: _ => throw new TaskCanceledException());

        var results = await service.LookupAsync(IocType.Ip, "8.8.8.8", _jobId);

        Assert.Equal(2, results.Count);
        Assert.All(results, r =>
        {
            Assert.False(r.FromLiveApi);
            Assert.Contains("timeout", r.RawResponse);
        });
    }

    [Fact]
    public async Task Missing_keys_fall_back_without_any_http_call()
    {
        var vtHandler = new StubHttpMessageHandler(_ => OkVtStats(90, 0, 0, 0));
        var abuseHandler = new StubHttpMessageHandler(_ => OkAbuse(100));
        var service = CreateService(
            options: new ThreatIntelOptions { VirusTotalApiKey = "", AbuseIpDbApiKey = "" },
            vtHandler: vtHandler, abuseHandler: abuseHandler);

        var results = await service.LookupAsync(IocType.Domain, "paypal-secure.xyz", _jobId);

        var vt = Assert.Single(results);
        Assert.False(vt.FromLiveApi);
        Assert.Contains("missing_api_key", vt.RawResponse);
        Assert.Equal(0.55, vt.MaliciousScore, precision: 6); // tld 0.25 + brand 0.30
        Assert.Equal(0, vtHandler.CallCount);
        Assert.Equal(0, abuseHandler.CallCount);
    }

    [Fact]
    public async Task Second_lookup_within_cache_window_hits_cache()
    {
        var vtHandler = new StubHttpMessageHandler(_ => OkVtStats(10, 0, 80, 0));
        var service = CreateService(vtHandler: vtHandler);

        var first = await service.LookupAsync(IocType.Domain, "cached.example", _jobId);
        var second = await service.LookupAsync(IocType.Domain, "cached.example", _jobId);

        var firstVt = Assert.Single(first);
        var secondVt = Assert.Single(second);
        Assert.Equal(firstVt.Id, secondVt.Id);
        Assert.True(secondVt.FromLiveApi); // cached row keeps its original flag
        Assert.Equal(1, vtHandler.CallCount);
        Assert.Equal(1, await _db.ThreatIntelResults.CountAsync());
    }

    [Fact]
    public async Task Expired_cache_entry_triggers_fresh_lookup()
    {
        _db.Iocs.Add(new Ioc
        {
            Id = Guid.NewGuid(), JobId = _jobId,
            Type = IocType.Domain, Value = "stale.example", ExtractedBy = IocExtractor.Rule
        });
        _db.ThreatIntelResults.Add(new ThreatIntelResult
        {
            Id = Guid.NewGuid(),
            IocId = _db.Iocs.Local.Single(i => i.Value == "stale.example").Id,
            Source = ThreatIntelSource.VirusTotal,
            RawResponse = "{}",
            MaliciousScore = 0.9,
            FromLiveApi = true,
            LookedUpAt = DateTimeOffset.UtcNow.AddHours(-48)
        });
        await _db.SaveChangesAsync();

        var vtHandler = new StubHttpMessageHandler(_ => OkVtStats(0, 0, 90, 0));
        var service = CreateService(vtHandler: vtHandler, options: new ThreatIntelOptions
        {
            VirusTotalApiKey = "vt-key", CacheHours = 24
        });

        var results = await service.LookupAsync(IocType.Domain, "stale.example", _jobId);

        Assert.Single(results);
        Assert.Equal(1, vtHandler.CallCount);
        Assert.Equal(2, await _db.ThreatIntelResults.CountAsync());
    }

    [Fact]
    public async Task Cache_is_shared_across_jobs()
    {
        var otherJobId = Guid.NewGuid();
        _db.AnalysisJobs.Add(new AnalysisJob
        {
            Id = otherJobId, FileName = "other.eml",
            FileType = ArtifactType.Eml, StoragePath = "/tmp/other.eml"
        });
        await _db.SaveChangesAsync();

        var vtHandler = new StubHttpMessageHandler(_ => OkVtStats(0, 0, 90, 0));
        var service = CreateService(vtHandler: vtHandler);

        await service.LookupAsync(IocType.Domain, "shared.example", _jobId);
        var second = await service.LookupAsync(IocType.Domain, "shared.example", otherJobId);

        Assert.Single(second);
        Assert.Equal(1, vtHandler.CallCount);
        Assert.Equal(1, await _db.ThreatIntelResults.CountAsync());
    }

    [Fact]
    public async Task Email_ioc_has_no_applicable_source()
    {
        var service = CreateService();

        var results = await service.LookupAsync(IocType.Email, "a@b.example", _jobId);

        Assert.Empty(results);
        Assert.Equal(0, await _db.ThreatIntelResults.CountAsync());
    }

    /// <summary>
    /// InMemory cannot map the pgvector column — it is irrelevant here, so the
    /// test context ignores it.
    /// </summary>
    private sealed class TestDbContext(DbContextOptions<VigilDbContext> options) : VigilDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<IncidentEmbedding>().Ignore(e => e.Embedding);
        }
    }
}
