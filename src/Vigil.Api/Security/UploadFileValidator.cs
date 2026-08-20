namespace Vigil.Api.Security;

/// <summary>
/// Content sniffing for uploaded artifacts. The extension check alone is not
/// enough — anyone can rename malware.exe to report.eml. We reject known
/// executable/archive signatures, NUL bytes (binary payloads), and enforce a
/// minimal per-type shape (JSON starts with { or [, EML has header lines).
/// </summary>
public static class UploadFileValidator
{
    private const int SniffBytes = 4096;

    // MZ (Windows PE), ELF, ZIP/OOXML wrapper, Mach-O (32/64-bit), PDF.
    private static readonly byte[][] DangerousSignatures =
    [
        [(byte)'M', (byte)'Z'],
        [0x7F, (byte)'E', (byte)'L', (byte)'F'],
        [(byte)'P', (byte)'K', 0x03, 0x04],
        [0xFE, 0xED, 0xFA, 0xCE],
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCE, 0xFA, 0xED, 0xFE],
        [0xCF, 0xFA, 0xED, 0xFE],
        [(byte)'%', (byte)'P', (byte)'D', (byte)'F']
    ];

    public static async Task<(bool Ok, string? Error)> ValidateAsync(
        IFormFile file, string extension, CancellationToken cancellationToken)
    {
        await using var stream = file.OpenReadStream();
        var buffer = new byte[SniffBytes];
        var read = await stream.ReadAsync(buffer.AsMemory(0, SniffBytes), cancellationToken);
        var sample = buffer.AsSpan(0, read);

        foreach (var signature in DangerousSignatures)
        {
            if (sample.StartsWith(signature))
            {
                return (false, "File content looks like an executable or archive, not a log artifact.");
            }
        }

        if (sample.IndexOf((byte)0) >= 0)
        {
            return (false, "File contains binary data; only text artifacts (.eml/.csv/.json) are accepted.");
        }

        return extension.ToLowerInvariant() switch
        {
            ".json" => ValidateJsonShape(sample),
            ".eml" => ValidateEmlShape(sample),
            _ => (true, null) // .csv: text check above is enough
        };
    }

    private static (bool, string?) ValidateJsonShape(ReadOnlySpan<byte> sample)
    {
        foreach (var b in sample)
        {
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                continue;
            }

            return b is (byte)'{' or (byte)'['
                ? (true, null)
                : (false, "File has a .json extension but the content is not JSON.");
        }

        return (false, "File is empty.");
    }

    private static (bool, string?) ValidateEmlShape(ReadOnlySpan<byte> sample)
    {
        // RFC 822 headers are "Name: value" lines — every real .eml starts with them.
        var text = System.Text.Encoding.UTF8.GetString(sample);
        var firstLineEnd = text.IndexOf('\n', StringComparison.Ordinal);
        var firstLine = firstLineEnd > 0 ? text[..firstLineEnd] : text;

        return firstLine.Contains(": ", StringComparison.Ordinal)
            ? (true, null)
            : (false, "File has an .eml extension but does not start with email headers.");
    }
}
