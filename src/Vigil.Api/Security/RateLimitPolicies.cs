namespace Vigil.Api.Security;

/// <summary>Named rate-limit policies (see Program.cs for the limits).</summary>
public static class RateLimitPolicies
{
    public const string Uploads = "uploads";
    public const string Auth = "auth";
}
