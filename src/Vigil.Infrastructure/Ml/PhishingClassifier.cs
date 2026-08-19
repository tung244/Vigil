using Microsoft.Extensions.Logging;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Vigil.Core.Ml;

namespace Vigil.Infrastructure.Ml;

/// <summary>
/// ONNX port of the Python <c>PhishingClassifier</c> (bastion/models/ml_models.py):
/// loads the exported <c>ealvaradob/bert-finetuned-phishing</c> weights once
/// (lazy, thread-safe singleton via DI) and scores subject+body with
/// <c>Microsoft.ML.OnnxRuntime</c>. Tokenization uses
/// <see cref="BertWordPieceTokenizer"/> over the exported vocab.txt so token ids
/// match HuggingFace exactly (verified against tests/fixtures/ml_baseline.json
/// inputIds — Microsoft.ML.Tokenizers' BertTokenizer drops punctuation tokens
/// and could not reach parity). The input shape mirrors the Python pipeline:
/// "subject [SEP] body[:512]", truncated to 512 tokens.
/// </summary>
public sealed class PhishingClassifier : IPhishingClassifier, IDisposable
{
    /// <summary>BERT max sequence length; matches the HF tokenizer call in the Python pipeline.</summary>
    public const int MaxTokenCount = 512;

    /// <summary>Body character cap applied before tokenization, as in the Python pipeline.</summary>
    public const int MaxBodyChars = 512;

    /// <summary>Model config (id2label): 0 = benign, 1 = phishing.</summary>
    public const int PhishingLabelIndex = 1;

    private readonly ILogger<PhishingClassifier> _logger;
    private readonly Lazy<(InferenceSession Session, BertWordPieceTokenizer Tokenizer)> _model;
    private readonly object _inferenceLock = new();

    public PhishingClassifier(
        string modelPath,
        string vocabPath,
        double threshold,
        bool enabled,
        ILogger<PhishingClassifier> logger)
    {
        _logger = logger;
        Enabled = enabled;
        Threshold = threshold;
        _model = new Lazy<(InferenceSession, BertWordPieceTokenizer)>(
            () => Load(modelPath, vocabPath),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public bool Enabled { get; }

    public double Threshold { get; }

    public double Classify(string? subject, string body)
    {
        if (!Enabled)
        {
            throw new InvalidOperationException(
                "Classifier is disabled (Ml:Enabled=false); check Enabled before calling Classify.");
        }

        var ids = EncodeIds(subject, body);
        var logits = RunInference(ids);
        return SoftmaxPhishingProbability(logits);
    }

    /// <summary>
    /// Combines subject/body exactly like the Python pipeline and returns the
    /// BERT token ids (special tokens included, truncated to 512). Public so the
    /// parity tests can assert token-level equality with the HF tokenizer.
    /// </summary>
    public IReadOnlyList<int> EncodeIds(string? subject, string body)
    {
        var text = $"{subject ?? string.Empty} [SEP] {Truncate(body, MaxBodyChars)}";
        var (_, tokenizer) = _model.Value;
        return tokenizer.Encode(text, MaxTokenCount); // tokenizer is read-only after load
    }

    private (InferenceSession Session, BertWordPieceTokenizer Tokenizer) Load(string modelPath, string vocabPath)
    {
        _logger.LogInformation("Loading phishing ONNX model from {ModelPath}", modelPath);
        var session = new InferenceSession(modelPath);
        var tokenizer = BertWordPieceTokenizer.LoadFromVocabFile(vocabPath);

        _logger.LogInformation(
            "Phishing model loaded; inputs: {Inputs}",
            string.Join(", ", session.InputMetadata.Keys));
        return (session, tokenizer);
    }

    private float[] RunInference(IReadOnlyList<int> ids)
    {
        var (session, _) = _model.Value;
        var length = ids.Count;
        var dimensions = new[] { 1, length };

        var inputIds = new DenseTensor<long>(dimensions);
        var attentionMask = new DenseTensor<long>(dimensions);
        var tokenTypeIds = new DenseTensor<long>(dimensions); // single sequence: all zeros
        for (var i = 0; i < length; i++)
        {
            inputIds[0, i] = ids[i];
            attentionMask[0, i] = 1;
        }

        // Feed only the inputs the exported graph actually declares.
        var available = session.InputMetadata.Keys;
        var inputs = new List<NamedOnnxValue>(3);
        if (available.Contains("input_ids"))
        {
            inputs.Add(NamedOnnxValue.CreateFromTensor("input_ids", inputIds));
        }

        if (available.Contains("attention_mask"))
        {
            inputs.Add(NamedOnnxValue.CreateFromTensor("attention_mask", attentionMask));
        }

        if (available.Contains("token_type_ids"))
        {
            inputs.Add(NamedOnnxValue.CreateFromTensor("token_type_ids", tokenTypeIds));
        }

        lock (_inferenceLock)
        {
            using var results = session.Run(inputs);
            return results.First(r => r.Name == "logits").AsEnumerable<float>().ToArray();
        }
    }

    internal static double SoftmaxPhishingProbability(float[] logits)
    {
        var max = logits.Max();
        double sum = 0;
        foreach (var logit in logits)
        {
            sum += Math.Exp(logit - max);
        }

        return Math.Exp(logits[PhishingLabelIndex] - max) / sum;
    }

    private static string Truncate(string value, int maxChars) =>
        value.Length <= maxChars ? value : value[..maxChars];

    public void Dispose()
    {
        if (_model.IsValueCreated)
        {
            _model.Value.Session.Dispose();
        }
    }
}
