using Microsoft.EntityFrameworkCore;
using Vigil.Core.Domain;

namespace Vigil.Infrastructure.Persistence;

public class VigilDbContext(DbContextOptions<VigilDbContext> options) : DbContext(options)
{
    public DbSet<AnalysisJob> AnalysisJobs => Set<AnalysisJob>();
    public DbSet<Tier1Result> Tier1Results => Set<Tier1Result>();
    public DbSet<Ioc> Iocs => Set<Ioc>();
    public DbSet<ThreatIntelResult> ThreatIntelResults => Set<ThreatIntelResult>();
    public DbSet<AnalysisReport> Reports => Set<AnalysisReport>();
    public DbSet<IncidentEmbedding> IncidentEmbeddings => Set<IncidentEmbedding>();
    public DbSet<CloudtrailLog> CloudtrailLogs => Set<CloudtrailLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasPostgresExtension("vector");

        modelBuilder.Entity<AnalysisJob>(e =>
        {
            e.ToTable("analysis_jobs");
            e.HasKey(x => x.Id);
            e.Property(x => x.FileType).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.CreatedAt);
        });

        modelBuilder.Entity<Tier1Result>(e =>
        {
            e.ToTable("tier1_results");
            e.HasKey(x => x.Id);
            e.Property(x => x.RuleCheckResults).HasColumnType("jsonb");
            e.Property(x => x.Verdict).HasConversion<string>().HasMaxLength(16);
            e.HasOne(x => x.Job).WithOne(j => j.Tier1Result)
                .HasForeignKey<Tier1Result>(x => x.JobId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Ioc>(e =>
        {
            e.ToTable("iocs");
            e.HasKey(x => x.Id);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.ExtractedBy).HasConversion<string>().HasMaxLength(16);
            e.HasOne(x => x.Job).WithMany(j => j.Iocs)
                .HasForeignKey(x => x.JobId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.Type, x.Value });
        });

        modelBuilder.Entity<ThreatIntelResult>(e =>
        {
            e.ToTable("threat_intel_results");
            e.HasKey(x => x.Id);
            e.Property(x => x.Source).HasConversion<string>().HasMaxLength(32);
            e.Property(x => x.RawResponse).HasColumnType("jsonb");
            e.HasOne(x => x.Ioc).WithMany(i => i.IntelResults)
                .HasForeignKey(x => x.IocId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.LookedUpAt);
        });

        modelBuilder.Entity<AnalysisReport>(e =>
        {
            e.ToTable("reports");
            e.HasKey(x => x.Id);
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(16);
            e.Property(x => x.MitreTechniques).HasColumnType("jsonb");
            e.Property(x => x.RecommendedActions).HasColumnType("jsonb");
            e.Property(x => x.EvidenceTrail).HasColumnType("jsonb");
            e.HasOne(x => x.Job).WithOne(j => j.Report)
                .HasForeignKey<AnalysisReport>(x => x.JobId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => x.RiskScore);
        });

        modelBuilder.Entity<IncidentEmbedding>(e =>
        {
            e.ToTable("incident_embeddings");
            e.HasKey(x => x.Id);
            e.Property(x => x.Embedding).HasColumnType("vector(384)");
            e.HasOne(x => x.Report).WithOne(r => r.Embedding)
                .HasForeignKey<IncidentEmbedding>(x => x.ReportId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<CloudtrailLog>(e =>
        {
            e.ToTable("cloudtrail_logs");
            e.HasKey(x => x.Id);
            e.Property(x => x.RawEvent).HasColumnType("jsonb");
            e.HasIndex(x => x.SourceIp);
            e.HasIndex(x => x.EventTime);
        });
    }
}
