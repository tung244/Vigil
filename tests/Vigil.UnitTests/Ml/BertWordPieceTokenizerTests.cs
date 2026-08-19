using Vigil.Core.Ml;
using Xunit;

namespace Vigil.UnitTests.Ml;

/// <summary>
/// Tokenizer parity with HuggingFace <c>BertTokenizer</c> (uncased) for
/// <c>ealvaradob/bert-finetuned-phishing</c>. Every expected id sequence below
/// was produced by the HF tokenizer itself (see tools/export_onnx.py) over a
/// minimal hand-built vocab that carries the same ids as the real vocab.txt.
/// End-to-end parity on the dataset .eml files is covered by MlParityTests.
/// </summary>
public class BertWordPieceTokenizerTests
{
    private static readonly BertWordPieceTokenizer Tokenizer = new(new Dictionary<string, int>
    {
        ["[PAD]"] = 0, ["[UNK]"] = 100, ["[CLS]"] = 101, ["[SEP]"] = 102, ["[MASK]"] = 103,
        ["urgent"] = 13661, [":"] = 1024, ["verify"] = 20410, ["your"] = 2115,
        ["account"] = 4070, ["!"] = 999,
        ["click"] = 11562, ["here"] = 2182, ["reset"] = 25141, ["password"] = 20786,
        ["cafe"] = 7668, ["naive"] = 15743, ["resume"] = 13746,
        ["unbelievable"] = 23653, ["extra"] = 4469, ["##ord"] = 8551, ["##ina"] = 3981,
        ["##rily"] = 11272, ["##long"] = 10052, ["##word"] = 18351, ["##with"] = 24415,
        ["##outs"] = 12166, ["##pace"] = 15327, ["##s"] = 2015,
        ["call"] = 2655, ["09"] = 5641, ["##0"] = 2692, ["-"] = 1011, ["123"] = 13138,
        ["45"] = 3429, ["##6"] = 2575, ["##7"] = 2581, ["now"] = 2085,
        ["中"] = 1746, ["文"] = 1861, ["word"] = 2773,
    });

    [Fact]
    public void Encodes_sentence_with_punctuation_like_huggingface() =>
        Assert.Equal(
            [101, 13661, 1024, 20410, 2115, 4070, 999, 102],
            Tokenizer.Encode("Urgent: verify your account!"));

    [Fact]
    public void Sep_literal_in_text_maps_to_special_token_not_pieces() =>
        Assert.Equal(
            [101, 11562, 2182, 102, 25141, 2115, 20786, 102],
            Tokenizer.Encode("Click here [SEP] reset your password"));

    [Fact]
    public void Accents_are_stripped_for_uncased_vocab() =>
        Assert.Equal(
            [101, 7668, 15743, 13746, 102],
            Tokenizer.Encode("Café naïve résumé"));

    [Fact]
    public void Long_words_split_into_wordpieces() =>
        Assert.Equal(
            [101, 23653, 4469, 8551, 3981, 11272, 10052, 18351, 24415, 12166, 15327, 2015, 102],
            Tokenizer.Encode("unbelievable extraordinarilylongwordwithoutspaces"));

    [Fact]
    public void Phone_like_numbers_split_like_huggingface() =>
        Assert.Equal(
            [101, 2655, 5641, 2692, 1011, 13138, 1011, 3429, 2575, 2581, 2085, 102],
            Tokenizer.Encode("Call 090-123-4567 now"));

    [Fact]
    public void Unknown_tokens_become_unk() =>
        Assert.Equal([101, 100, 102], Tokenizer.Encode("\U0001F389\U0001F389"));

    [Fact]
    public void Cjk_characters_are_tokenized_individually() =>
        Assert.Equal([101, 1746, 1861, 100, 100, 102], Tokenizer.Encode("中文测试"));

    [Fact]
    public void Truncates_to_max_tokens_keeping_cls_and_sep()
    {
        var ids = Tokenizer.Encode(string.Join(' ', Enumerable.Repeat("word", 600)));

        Assert.Equal(512, ids.Count);
        Assert.Equal(101, ids[0]);
        Assert.Equal(102, ids[^1]);
        Assert.All(ids.Skip(1).Take(510), id => Assert.Equal(2773, id));
    }
}
