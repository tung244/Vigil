using System.Text;

namespace Vigil.Core.Tier1;

/// <summary>
/// Lenient CSV parser for CloudTrail-style log exports: header-driven column
/// mapping (case-insensitive), quoted-field support, rows with missing or
/// extra columns tolerated (the historical dataset has truncated rows).
/// </summary>
public static class CsvLogParser
{
    private static readonly Dictionary<string, string> ColumnAliases =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["eventtime"] = nameof(CsvLogRecord.EventTime),
            ["time"] = nameof(CsvLogRecord.EventTime),
            ["eventname"] = nameof(CsvLogRecord.EventName),
            ["event"] = nameof(CsvLogRecord.EventName),
            ["sourceipaddress"] = nameof(CsvLogRecord.SourceIp),
            ["sourceip"] = nameof(CsvLogRecord.SourceIp),
            ["ip"] = nameof(CsvLogRecord.SourceIp),
            ["useridentityusername"] = nameof(CsvLogRecord.UserName),
            ["username"] = nameof(CsvLogRecord.UserName),
            ["user"] = nameof(CsvLogRecord.UserName),
            ["errorcode"] = nameof(CsvLogRecord.ErrorCode),
            ["errormessage"] = nameof(CsvLogRecord.ErrorMessage),
            ["useragent"] = nameof(CsvLogRecord.UserAgent),
        };

    /// <summary>Parses CSV content; the first non-empty line must be the header.</summary>
    public static List<CsvLogRecord> Parse(string content)
    {
        var records = new List<CsvLogRecord>();
        if (string.IsNullOrWhiteSpace(content))
        {
            return records;
        }

        using var reader = new StringReader(content);

        string? headerLine = reader.ReadLine();
        while (headerLine is not null && string.IsNullOrWhiteSpace(headerLine))
        {
            headerLine = reader.ReadLine();
        }

        if (headerLine is null)
        {
            return records;
        }

        var headers = SplitLine(headerLine)
            .Select(h => ColumnAliases.TryGetValue(h.Trim(), out var mapped) ? mapped : null)
            .ToList();
        var rawHeaders = SplitLine(headerLine).Select(h => h.Trim()).ToList();

        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            var fields = SplitLine(line);
            var rawFields = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 0; i < rawHeaders.Count && i < fields.Count; i++)
            {
                var key = Sigma.SigmaFieldNormalizer.Normalize(rawHeaders[i]);
                if (key.Length > 0)
                {
                    rawFields[key] = fields[i].Trim();
                }
            }

            var record = new CsvLogRecord
            {
                EventTime = Field(headers, fields, nameof(CsvLogRecord.EventTime)),
                EventName = Field(headers, fields, nameof(CsvLogRecord.EventName)),
                SourceIp = Field(headers, fields, nameof(CsvLogRecord.SourceIp)),
                UserName = Field(headers, fields, nameof(CsvLogRecord.UserName)),
                ErrorCode = Field(headers, fields, nameof(CsvLogRecord.ErrorCode)),
                ErrorMessage = Field(headers, fields, nameof(CsvLogRecord.ErrorMessage)),
                UserAgent = Field(headers, fields, nameof(CsvLogRecord.UserAgent)),
                Fields = rawFields,
            };
            records.Add(record);
        }

        return records;
    }

    private static string Field(List<string?> headers, List<string> fields, string column)
    {
        var index = headers.IndexOf(column);
        return index >= 0 && index < fields.Count ? fields[index].Trim() : string.Empty;
    }

    /// <summary>Splits one CSV line, honoring double-quoted fields with "" escapes.</summary>
    private static List<string> SplitLine(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;

        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    current.Append(c);
                }
            }
            else if (c == '"')
            {
                inQuotes = true;
            }
            else if (c == ',')
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(c);
            }
        }

        fields.Add(current.ToString());
        return fields;
    }
}
