using Vigil.Api.Auth;
using Vigil.Api.Security;

namespace Vigil.Api.Endpoints;

public static class AuthEndpoints
{
    public sealed record LoginRequest(string Username, string Password);
    public sealed record LoginResponse(string Token, int ExpiresInMinutes);

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/login", Login)
            .RequireRateLimiting(RateLimitPolicies.Auth);

        return app;
    }

    private static IResult Login(LoginRequest request, IConfiguration configuration, TokenService tokens)
    {
        var expectedUser = configuration["Auth:AdminUser"] ?? "admin";
        var expectedPassword = configuration["Auth:AdminPassword"] ?? string.Empty;

        // Constant-time-ish comparison is overkill here; the rate limiter on
        // this endpoint is the real brute-force mitigation.
        if (!string.Equals(request.Username, expectedUser, StringComparison.Ordinal)
            || expectedPassword.Length == 0
            || !string.Equals(request.Password, expectedPassword, StringComparison.Ordinal))
        {
            return Results.Unauthorized();
        }

        var token = tokens.CreateToken(request.Username);
        return Results.Ok(new LoginResponse(token, (int)(tokens.TokenLifetime.TotalMinutes)));
    }
}
