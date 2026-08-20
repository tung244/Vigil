using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Vigil.Api.Auth;
using Vigil.Api.Endpoints;
using Vigil.Api.Security;
using Vigil.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// Local overrides (appsettings.*.Local.json) are gitignored — secrets never
// enter git history.
builder.Configuration.AddJsonFile("appsettings.Development.Local.json", optional: true, reloadOnChange: true);

builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

builder.Services.AddOpenApi();
builder.Services.AddVigilPersistence(builder.Configuration);
builder.Services.AddVigilMessaging(builder.Configuration);

// ── Auth: single SOC user, JWT bearer ───────────────────────────────────────
var tokenService = new TokenService(builder.Configuration);
builder.Services.AddSingleton(tokenService);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => options.TokenValidationParameters = tokenService.BuildValidationParameters());
builder.Services.AddAuthorization();

// ── Rate limiting: uploads and login are the abuse-prone endpoints ─────────
// Limits are read from the live IConfiguration per request (not captured at
// startup) so test hosts and hot config changes take effect immediately.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy(RateLimitPolicies.Uploads, httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = httpContext.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue("RateLimiting:UploadPermitLimit", 10),
                Window = TimeSpan.FromSeconds(httpContext.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue("RateLimiting:WindowSeconds", 60)),
                QueueLimit = 0
            }));

    options.AddPolicy(RateLimitPolicies.Auth, httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = httpContext.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue("RateLimiting:AuthPermitLimit", 5),
                Window = TimeSpan.FromSeconds(httpContext.RequestServices.GetRequiredService<IConfiguration>()
                    .GetValue("RateLimiting:WindowSeconds", 60)),
                QueueLimit = 0
            }));
});

// ── CORS: any localhost port in dev; explicit allow-list everywhere else ────
const string devCorsPolicy = "ViteDev";
const string prodCorsPolicy = "Configured";
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

    var prodOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
    options.AddPolicy(prodCorsPolicy, policy =>
    {
        if (prodOrigins.Length > 0)
        {
            policy.WithOrigins(prodOrigins).AllowAnyHeader().AllowAnyMethod();
        }
    });
});

var app = builder.Build();

// ── Security headers on every response (OWASP secure headers project) ───────
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    // This is a JSON API — no reason for the browser to load any resource.
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseCors(devCorsPolicy);
}
else
{
    app.UseCors(prodCorsPolicy);
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "Vigil.Api" }));
app.MapAuthEndpoints();
app.MapJobEndpoints();
app.MapStatsEndpoints();

app.Run();

// Exposed for WebApplicationFactory-based integration tests.
public partial class Program;
