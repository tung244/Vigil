using System.Globalization;
using System.Text;

namespace Vigil.Core.Ml;

/// <summary>
/// Minimal BERT WordPiece tokenizer matching HuggingFace <c>BertTokenizer</c>
/// (uncased) exactly: special tokens are split out before basic tokenization,
/// basic tokenization lowercases + strips accents + splits punctuation and CJK,
/// and wordpiece does greedy longest-match with "##" continuation markers.
/// Lives in Vigil.Core (pure text transformation, like <c>PiiScrubber</c>) so
/// the token-id parity with the Python pipeline is unit-testable without the
/// ONNX runtime. Written because Microsoft.ML.Tokenizers' BertTokenizer
/// normalizes away punctuation tokens, diverging from the HF tokenizer.
/// </summary>
public sealed class BertWordPieceTokenizer
{
    /// <summary>BERT max sequence length, including [CLS] and [SEP].</summary>
    public const int DefaultMaxTokens = 512;

    private const int MaxCharsPerToken = 100;

    // Split out verbatim (case-sensitive) before basic tokenization, exactly
    // like HF's never_split handling of special tokens.
    private static readonly string[] SpecialTokens = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"];

    private readonly IReadOnlyDictionary<string, int> _vocab;
    private readonly int _unkId;
    private readonly int _clsId;
    private readonly int _sepId;

    public BertWordPieceTokenizer(IReadOnlyDictionary<string, int> vocab)
    {
        _vocab = vocab;
        _unkId = vocab["[UNK]"];
        _clsId = vocab["[CLS]"];
        _sepId = vocab["[SEP]"];
    }

    /// <summary>Loads a BERT vocab.txt: token per line, line index = token id.</summary>
    public static BertWordPieceTokenizer LoadFromVocabFile(string vocabPath)
    {
        var vocab = new Dictionary<string, int>(StringComparer.Ordinal);
        var id = 0;
        foreach (var line in File.ReadLines(vocabPath))
        {
            // vocab.txt tokens contain no whitespace; keep the raw line.
            if (line.Length > 0)
            {
                vocab.TryAdd(line, id);
            }

            id++;
        }

        return new BertWordPieceTokenizer(vocab);
    }

    /// <summary>
    /// Encodes text to BERT input ids: [CLS] + wordpiece ids + [SEP],
    /// truncated to <paramref name="maxTokens"/> like HF's
    /// <c>truncation=True, max_length=512</c>.
    /// </summary>
    public IReadOnlyList<int> Encode(string text, int maxTokens = DefaultMaxTokens)
    {
        var pieces = new List<string>();
        foreach (var segment in SplitOnSpecialTokens(text))
        {
            if (SpecialTokens.Contains(segment, StringComparer.Ordinal))
            {
                pieces.Add(segment);
                continue;
            }

            foreach (var token in BasicTokenize(segment))
            {
                WordPiece(token, pieces);
            }
        }

        if (pieces.Count > maxTokens - 2)
        {
            pieces.RemoveRange(maxTokens - 2, pieces.Count - (maxTokens - 2));
        }

        var ids = new List<int>(pieces.Count + 2) { _clsId };
        foreach (var piece in pieces)
        {
            ids.Add(_vocab.GetValueOrDefault(piece, _unkId));
        }

        ids.Add(_sepId);
        return ids;
    }

    private static IEnumerable<string> SplitOnSpecialTokens(string text)
    {
        var position = 0;
        while (position < text.Length)
        {
            var nearestIndex = -1;
            string? nearestToken = null;
            foreach (var special in SpecialTokens)
            {
                var index = text.IndexOf(special, position, StringComparison.Ordinal);
                if (index >= 0 && (nearestIndex < 0 || index < nearestIndex))
                {
                    nearestIndex = index;
                    nearestToken = special;
                }
            }

            if (nearestToken is null)
            {
                yield return text[position..];
                yield break;
            }

            if (nearestIndex > position)
            {
                yield return text[position..nearestIndex];
            }

            yield return nearestToken;
            position = nearestIndex + nearestToken.Length;
        }

        if (text.Length == 0)
        {
            yield break;
        }
    }

    /// <summary>HF BasicTokenizer: clean, split CJK, lowercase, strip accents, split punctuation.</summary>
    private static IEnumerable<string> BasicTokenize(string text)
    {
        var cleaned = CleanText(text);
        var cjkSplit = SplitCjk(cleaned);

        foreach (var whitespaceToken in WhitespaceSplit(cjkSplit))
        {
            var lowered = StripAccents(whitespaceToken.ToLowerInvariant());
            foreach (var token in SplitOnPunctuation(lowered))
            {
                yield return token;
            }
        }
    }

    private static string CleanText(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            var value = rune.Value;
            if (value is 0 or 0xFFFD || (Rune.GetUnicodeCategory(rune) == UnicodeCategory.Control && value is not ('\t' or '\n' or '\r')))
            {
                continue;
            }

            builder.Append(Rune.IsWhiteSpace(rune) ? ' ' : rune.ToString());
        }

        return builder.ToString();
    }

    private static string SplitCjk(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            if (IsCjk(rune.Value))
            {
                builder.Append(' ').Append(rune.ToString()).Append(' ');
            }
            else
            {
                builder.Append(rune.ToString());
            }
        }

        return builder.ToString();
    }

    private static IEnumerable<string> WhitespaceSplit(string text)
    {
        var builder = new StringBuilder();
        foreach (var rune in text.EnumerateRunes())
        {
            if (Rune.IsWhiteSpace(rune))
            {
                if (builder.Length > 0)
                {
                    yield return builder.ToString();
                    builder.Clear();
                }
            }
            else
            {
                builder.Append(rune.ToString());
            }
        }

        if (builder.Length > 0)
        {
            yield return builder.ToString();
        }
    }

    private static string StripAccents(string text)
    {
        var decomposed = text.Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(decomposed.Length);
        foreach (var rune in decomposed.EnumerateRunes())
        {
            if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.NonSpacingMark)
            {
                builder.Append(rune.ToString());
            }
        }

        return builder.ToString();
    }

    private static IEnumerable<string> SplitOnPunctuation(string text)
    {
        var builder = new StringBuilder();
        foreach (var rune in text.EnumerateRunes())
        {
            if (IsPunctuation(rune))
            {
                if (builder.Length > 0)
                {
                    yield return builder.ToString();
                    builder.Clear();
                }

                yield return rune.ToString();
            }
            else
            {
                builder.Append(rune.ToString());
            }
        }

        if (builder.Length > 0)
        {
            yield return builder.ToString();
        }
    }

    /// <summary>Greedy longest-match-first wordpiece; appends "[UNK]" when a token cannot be split.</summary>
    private void WordPiece(string token, List<string> output)
    {
        var runes = token.EnumerateRunes().Select(r => r.ToString()).ToList();
        if (runes.Count > MaxCharsPerToken)
        {
            output.Add("[UNK]");
            return;
        }

        var start = 0;
        while (start < runes.Count)
        {
            var matched = false;
            for (var end = runes.Count; end > start; end--)
            {
                var piece = string.Concat(runes.Take(end).Skip(start));
                if (start > 0)
                {
                    piece = "##" + piece;
                }

                if (_vocab.ContainsKey(piece))
                {
                    output.Add(piece);
                    start = end;
                    matched = true;
                    break;
                }
            }

            if (!matched)
            {
                output.Add("[UNK]");
                return;
            }
        }
    }

    private static bool IsPunctuation(Rune rune)
    {
        var value = rune.Value;
        if (value is >= 33 and <= 47 or >= 58 and <= 64 or >= 91 and <= 96 or >= 123 and <= 126)
        {
            return true;
        }

        return Rune.GetUnicodeCategory(rune) is
            UnicodeCategory.ConnectorPunctuation or UnicodeCategory.DashPunctuation
            or UnicodeCategory.OpenPunctuation or UnicodeCategory.ClosePunctuation
            or UnicodeCategory.InitialQuotePunctuation or UnicodeCategory.FinalQuotePunctuation
            or UnicodeCategory.OtherPunctuation;
    }

    private static bool IsCjk(int value) =>
        value is >= 0x4E00 and <= 0x9FFF
            or >= 0x3400 and <= 0x4DBF
            or >= 0x20000 and <= 0x2A6DF
            or >= 0x2A700 and <= 0x2B73F
            or >= 0x2B740 and <= 0x2B81F
            or >= 0x2B820 and <= 0x2CEAF
            or >= 0xF900 and <= 0xFAFF
            or >= 0x2F800 and <= 0x2FA1F;
}
