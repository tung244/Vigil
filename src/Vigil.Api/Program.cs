using Vigil.Api.Endpoints;
using Vigil.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddVigilPersistence(builder.Configuration);
builder.Services.AddVigilMessaging(builder.Configuration);

const string devCorsPolicy = "ViteDev";
builder.Services.AddCors(options =>
{
    options.AddPolicy(devCorsPolicy, policy =>
        policy.SetIsOriginAllowed(origin =>
                {
                    // Any localhost port — Vite moves to 5174+ when 5173 is busy.
                    return Uri.TryCreate(origin, UriKind.Absolute, out var uri)
                        && uri.Host is "localhost" or "127.0.0.1";
                })
            .AllowAnyHeader()
            .AllowAnyMethod());
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseCors(devCorsPolicy);
}

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "Vigil.Api" }));
app.MapJobEndpoints();

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program;
