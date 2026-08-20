using System.Text;

namespace Vigil.Core.Tier1.Sigma;

/// <summary>
/// Field-name normalization so Sigma rules written against CloudTrail JSON
/// ("userIdentity.userName") match our flattened CSV headers
/// ("userIdentityuserName"): lowercase, keep alphanumerics only.
/// </summary>
public static class SigmaFieldNormalizer
{
    public static string Normalize(string fieldName)
    {
        var builder = new StringBuilder(fieldName.Length);
        foreach (var c in fieldName)
        {
            if (char.IsLetterOrDigit(c))
            {
                builder.Append(char.ToLowerInvariant(c));
            }
        }

        return builder.ToString();
    }
}
