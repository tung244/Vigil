using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Pgvector;

#nullable disable

namespace Vigil.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterDatabase()
                .Annotation("Npgsql:PostgresExtension:vector", ",,");

            migrationBuilder.CreateTable(
                name: "analysis_jobs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FileName = table.Column<string>(type: "text", nullable: false),
                    FileType = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    StoragePath = table.Column<string>(type: "text", nullable: false),
                    CurrentStep = table.Column<string>(type: "text", nullable: true),
                    ErrorMessage = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    FinishedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_analysis_jobs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "cloudtrail_logs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EventTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    EventName = table.Column<string>(type: "text", nullable: false),
                    SourceIp = table.Column<string>(type: "text", nullable: true),
                    UserIdentity = table.Column<string>(type: "text", nullable: true),
                    AwsRegion = table.Column<string>(type: "text", nullable: true),
                    RawEvent = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_cloudtrail_logs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "iocs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Value = table.Column<string>(type: "text", nullable: false),
                    ExtractedBy = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_iocs", x => x.Id);
                    table.ForeignKey(
                        name: "FK_iocs_analysis_jobs_JobId",
                        column: x => x.JobId,
                        principalTable: "analysis_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "reports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    RiskScore = table.Column<double>(type: "double precision", nullable: false),
                    Severity = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    SummaryMarkdown = table.Column<string>(type: "text", nullable: false),
                    MitreTechniques = table.Column<string>(type: "jsonb", nullable: false),
                    RecommendedActions = table.Column<string>(type: "jsonb", nullable: false),
                    EvidenceTrail = table.Column<string>(type: "jsonb", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_reports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_reports_analysis_jobs_JobId",
                        column: x => x.JobId,
                        principalTable: "analysis_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "tier1_results",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScrubbedPayload = table.Column<string>(type: "text", nullable: false),
                    RuleCheckResults = table.Column<string>(type: "jsonb", nullable: false),
                    MlScore = table.Column<double>(type: "double precision", nullable: true),
                    Verdict = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tier1_results", x => x.Id);
                    table.ForeignKey(
                        name: "FK_tier1_results_analysis_jobs_JobId",
                        column: x => x.JobId,
                        principalTable: "analysis_jobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "threat_intel_results",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    IocId = table.Column<Guid>(type: "uuid", nullable: false),
                    Source = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RawResponse = table.Column<string>(type: "jsonb", nullable: false),
                    MaliciousScore = table.Column<double>(type: "double precision", nullable: false),
                    FromLiveApi = table.Column<bool>(type: "boolean", nullable: false),
                    LookedUpAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_threat_intel_results", x => x.Id);
                    table.ForeignKey(
                        name: "FK_threat_intel_results_iocs_IocId",
                        column: x => x.IocId,
                        principalTable: "iocs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "incident_embeddings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    Embedding = table.Column<Vector>(type: "vector(384)", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_incident_embeddings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_incident_embeddings_reports_ReportId",
                        column: x => x.ReportId,
                        principalTable: "reports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_analysis_jobs_CreatedAt",
                table: "analysis_jobs",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_analysis_jobs_Status",
                table: "analysis_jobs",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_cloudtrail_logs_EventTime",
                table: "cloudtrail_logs",
                column: "EventTime");

            migrationBuilder.CreateIndex(
                name: "IX_cloudtrail_logs_SourceIp",
                table: "cloudtrail_logs",
                column: "SourceIp");

            migrationBuilder.CreateIndex(
                name: "IX_incident_embeddings_ReportId",
                table: "incident_embeddings",
                column: "ReportId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_iocs_JobId",
                table: "iocs",
                column: "JobId");

            migrationBuilder.CreateIndex(
                name: "IX_iocs_Type_Value",
                table: "iocs",
                columns: new[] { "Type", "Value" });

            migrationBuilder.CreateIndex(
                name: "IX_reports_JobId",
                table: "reports",
                column: "JobId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_reports_RiskScore",
                table: "reports",
                column: "RiskScore");

            migrationBuilder.CreateIndex(
                name: "IX_threat_intel_results_IocId",
                table: "threat_intel_results",
                column: "IocId");

            migrationBuilder.CreateIndex(
                name: "IX_threat_intel_results_LookedUpAt",
                table: "threat_intel_results",
                column: "LookedUpAt");

            migrationBuilder.CreateIndex(
                name: "IX_tier1_results_JobId",
                table: "tier1_results",
                column: "JobId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "cloudtrail_logs");

            migrationBuilder.DropTable(
                name: "incident_embeddings");

            migrationBuilder.DropTable(
                name: "threat_intel_results");

            migrationBuilder.DropTable(
                name: "tier1_results");

            migrationBuilder.DropTable(
                name: "reports");

            migrationBuilder.DropTable(
                name: "iocs");

            migrationBuilder.DropTable(
                name: "analysis_jobs");
        }
    }
}
