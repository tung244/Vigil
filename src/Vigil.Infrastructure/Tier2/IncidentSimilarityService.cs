using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Pgvector;
using Pgvector.EntityFrameworkCore;
using Vigil.Core.Domain;
using Vigil.Core.Ml;
using Vigil.Core.Tier2;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Infrastructure.Tier2;

/// <summary>
/// pgvector-backed incident similarity search (Step 9 RAG). Completed reports
/// are embedded (summary + IOC values) into <c>incident_embeddings</c>; before
/// synthesis, the current job's evidence is embedded and the top-k nearest
/// past incidents (cosine distance) are returned as prompt context.
///
/// Everything here is best-effort: when the embedding service is disabled or
/// its model is missing, both operations quietly no-op so the pipeline runs
/// unchanged (the service logs the reason once at load).
/// </summary>
public sealed class IncidentSimilarityService(
    VigilDbContext db,
    IEmbeddingService embedding,
    ILogger<IncidentSimilarityService> logger)
{
    public const int DefaultTopK = 3;

    /// <summary>Summary excerpt length shown in the synthesis prompt per similar incident.</summary>
    private const int MaxSummaryExcerptChars = 300;

    /// <summary>Character cap for text sent to the embedding model (cost/quality guard).</summary>
    private const int MaxEmbeddingTextChars = 2000;

    /// <summary>
    /// Returns the <paramref name="topK"/> most similar past incidents by
    /// cosine similarity of their report embeddings, excluding
    /// <paramref name="excludeJobId"/> (the job currently being synthesized).
    /// Empty when embeddings are unavailable or nothing is indexed yet.
    /// </summary>
    public async Task<IReadOnlyList<SimilarIncidentEvidence>> FindSimilarAsync(
        string queryText,
        Guid? excludeJobId,
        int topK = DefaultTopK,
        CancellationToken cancellationToken = default)
    {
        if (!embedding.Enabled)
        {
            return [];
        }

        var vector = await embedding.EmbedAsync(Truncate(queryText, MaxEmbeddingTextChars), cancellationToken);
        if (vector is null)
        {
            return [];
        }

        var queryVector = new Vector(vector);
        var matches = await db.IncidentEmbeddings.AsNoTracking()
            .Where(e => excludeJobId == null || e.Report.JobId != excludeJobId.Value)
            .OrderBy(e => e.Embedding.CosineDistance(queryVector))
            .Take(topK)
            .Select(e => new
            {
                e.ReportId,
                e.Report.RiskScore,
                e.Report.Severity,
                e.Report.SummaryMarkdown,
                RuleCheckResults = e.Report.Job.Tier1Result != null ? e.Report.Job.Tier1Result.RuleCheckResults : null,
                Distance = e.Embedding.CosineDistance(queryVector)
            })
            .ToListAsync(cancellationToken);

        var results = matches
            .Select(m => new SimilarIncidentEvidence(
                m.ReportId,
                m.RiskScore,
                m.Severity.ToString(),
                m.RuleCheckResults is null
                    ? []
                    : RuleIocSeeder.TryReadReport(m.RuleCheckResults)?.MatchedRules ?? [],
                Truncate(m.SummaryMarkdown, MaxSummaryExcerptChars),
                Similarity: 1.0 - m.Distance))
            .ToList();

        logger.LogInformation(
            "Incident similarity: {Count} matches (best similarity {Best:F3})",
            results.Count, results.Count == 0 ? 0 : results[0].Similarity);
        return results;
    }

    /// <summary>
    /// Embeds the report's summary + IOC values and stages the
    /// <see cref="IncidentEmbedding"/> row; the caller owns SaveChanges.
    /// </summary>
    public async Task IndexReportAsync(
        AnalysisReport report, IReadOnlyList<string> iocValues, CancellationToken cancellationToken = default)
    {
        if (!embedding.Enabled)
        {
            return;
        }

        var vector = await embedding.EmbedAsync(BuildIndexText(report.SummaryMarkdown, iocValues), cancellationToken);
        if (vector is null)
        {
            return;
        }

        db.IncidentEmbeddings.Add(new IncidentEmbedding
        {
            Id = Guid.NewGuid(),
            ReportId = report.Id,
            Embedding = new Vector(vector)
        });
    }

    /// <summary>Text embedded for a completed report: the analyst summary plus its IOC values.</summary>
    internal static string BuildIndexText(string summaryMarkdown, IReadOnlyList<string> iocValues)
    {
        var text = iocValues.Count == 0
            ? summaryMarkdown
            : summaryMarkdown + "\nIOCs: " + string.Join(", ", iocValues);
        return Truncate(text, MaxEmbeddingTextChars);
    }

    /// <summary>Retrieval query for a job in progress: matched rules, IOC values, email analysis summary.</summary>
    internal static string BuildRetrievalQuery(
        IReadOnlyList<string> matchedRules, IReadOnlyList<string> iocValues, string? emailAnalysisSummary)
    {
        var parts = new List<string>(2 + iocValues.Count + matchedRules.Count);
        if (!string.IsNullOrWhiteSpace(emailAnalysisSummary))
        {
            parts.Add(emailAnalysisSummary);
        }

        parts.AddRange(matchedRules);
        parts.AddRange(iocValues);
        return string.Join('\n', parts);
    }

    private static string Truncate(string value, int maxChars) =>
        value.Length <= maxChars ? value : value[..maxChars];
}
