using Microsoft.EntityFrameworkCore;
using Vigil.Api.Contracts;
using Vigil.Core.Domain;
using Vigil.Core.Messaging;
using Vigil.Infrastructure.Persistence;

namespace Vigil.Api.Endpoints;

public static class JobEndpoints
{
    private const long MaxUploadBytes = 10 * 1024 * 1024; // 10 MB

    private static readonly Dictionary<string, ArtifactType> AllowedExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            [".eml"] = ArtifactType.Eml,
            [".csv"] = ArtifactType.Csv,
            [".json"] = ArtifactType.Json
        };

    public static IEndpointRouteBuilder MapJobEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/jobs").WithTags("Jobs");

        group.MapPost("/", UploadArtifact).DisableAntiforgery();
        group.MapGet("/{id:guid}", GetJob);
        group.MapGet("/{id:guid}/report", GetReport);
        group.MapGet("/", ListJobs);

        return app;
    }

    private static async Task<IResult> UploadArtifact(
        IFormFile file,
        VigilDbContext db,
        IJobQueue queue,
        IConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (file.Length == 0)
        {
            return Results.BadRequest(new { error = "File is empty." });
        }

        if (file.Length > MaxUploadBytes)
        {
            return Results.BadRequest(new { error = $"File exceeds {MaxUploadBytes / 1024 / 1024} MB limit." });
        }

        var extension = Path.GetExtension(file.FileName);
        if (!AllowedExtensions.TryGetValue(extension, out var artifactType))
        {
            return Results.BadRequest(new
            {
                error = $"Unsupported file type '{extension}'. Allowed: {string.Join(", ", AllowedExtensions.Keys)}"
            });
        }

        var job = new AnalysisJob
        {
            Id = Guid.NewGuid(),
            FileName = Path.GetFileName(file.FileName),
            FileType = artifactType,
            Status = JobStatus.Queued,
            CurrentStep = "queued",
            StoragePath = string.Empty // set below, once we know the id
        };

        var uploadDir = configuration["Storage:UploadDir"] ?? "uploads";
        var absoluteDir = Path.GetFullPath(uploadDir);
        Directory.CreateDirectory(absoluteDir);

        var storagePath = Path.Combine(absoluteDir, $"{job.Id}{extension.ToLowerInvariant()}");
        await using (var stream = File.Create(storagePath))
        {
            await file.CopyToAsync(stream, cancellationToken);
        }

        job.StoragePath = storagePath;

        db.AnalysisJobs.Add(job);
        await db.SaveChangesAsync(cancellationToken);

        await queue.PublishJobAsync(job.Id, cancellationToken);

        var response = new JobAcceptedResponse(job.Id, job.Status.ToString());
        return Results.Accepted($"/api/jobs/{job.Id}", response);
    }

    private static async Task<IResult> GetJob(Guid id, VigilDbContext db, CancellationToken cancellationToken)
    {
        var job = await db.AnalysisJobs.AsNoTracking()
            .FirstOrDefaultAsync(j => j.Id == id, cancellationToken);

        if (job is null)
        {
            return Results.NotFound(new { error = $"Job {id} not found." });
        }

        var hasReport = await db.Reports.AnyAsync(r => r.JobId == id, cancellationToken);
        return Results.Ok(JobSummary.From(job, hasReport));
    }

    private static async Task<IResult> GetReport(Guid id, VigilDbContext db, CancellationToken cancellationToken)
    {
        var job = await db.AnalysisJobs.AsNoTracking()
            .Include(j => j.Report)
            .FirstOrDefaultAsync(j => j.Id == id, cancellationToken);

        if (job is null)
        {
            return Results.NotFound(new { error = $"Job {id} not found." });
        }

        if (job.Report is null)
        {
            return Results.Conflict(new
            {
                error = job.Status == JobStatus.Failed
                    ? $"Job {id} failed and has no report: {job.ErrorMessage}"
                    : $"Job {id} has no report yet (status {job.Status}, step {job.CurrentStep})."
            });
        }

        return Results.Ok(ReportResponse.From(job.Report));
    }

    private static async Task<IResult> ListJobs(
        VigilDbContext db,
        CancellationToken cancellationToken,
        int page = 1,
        int pageSize = 20)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var total = await db.AnalysisJobs.CountAsync(cancellationToken);
        var items = await db.AnalysisJobs.AsNoTracking()
            .OrderByDescending(j => j.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        var jobIds = items.Select(j => j.Id).ToList();
        var jobsWithReport = await db.Reports
            .Where(r => jobIds.Contains(r.JobId))
            .Select(r => r.JobId)
            .ToHashSetAsync(cancellationToken);

        return Results.Ok(new JobListResponse(
            items.Select(j => JobSummary.From(j, jobsWithReport.Contains(j.Id))).ToList(),
            total, page, pageSize));
    }
}
