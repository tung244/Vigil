var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "Vigil.Api" }));

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program;
