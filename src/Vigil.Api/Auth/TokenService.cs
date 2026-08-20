using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Vigil.Api.Auth;

/// <summary>
/// Issues signed JWTs for SOC dashboard users. Single-user system for now:
/// credentials come from config (Auth:AdminUser / Auth:AdminPassword), the
/// signing key from Auth:SigningKey (never the committed appsettings.json in
/// production — use env vars or appsettings.*.Local.json).
/// </summary>
public sealed class TokenService
{
    private readonly string _issuer;
    private readonly string _audience;
    private readonly SymmetricSecurityKey _key;
    private readonly TimeSpan _lifetime;

    public TimeSpan TokenLifetime => _lifetime;

    public TokenService(IConfiguration configuration)
    {
        _issuer = configuration["Auth:Issuer"] ?? "vigil";
        _audience = configuration["Auth:Audience"] ?? "vigil-soc";
        _lifetime = TimeSpan.FromMinutes(configuration.GetValue("Auth:TokenLifetimeMinutes", 720));

        var signingKey = configuration["Auth:SigningKey"];
        if (string.IsNullOrWhiteSpace(signingKey))
        {
            throw new InvalidOperationException(
                "Auth:SigningKey is not configured. Set it in appsettings.Development.Local.json " +
                "or the Auth__SigningKey environment variable (min 32 chars).");
        }

        if (signingKey.Length < 32)
        {
            throw new InvalidOperationException("Auth:SigningKey must be at least 32 characters.");
        }

        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
    }

    public string CreateToken(string username)
    {
        var credentials = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: [new Claim(ClaimTypes.Name, username), new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())],
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.Add(_lifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>Validation parameters shared by the bearer middleware.</summary>
    public TokenValidationParameters BuildValidationParameters() => new()
    {
        ValidIssuer = _issuer,
        ValidAudience = _audience,
        IssuerSigningKey = _key,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
}
