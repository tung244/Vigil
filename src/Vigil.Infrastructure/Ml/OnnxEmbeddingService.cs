using Microsoft.Extensions.Logging;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Vigil.Core.Ml;

namespace Vigil.Infrastructure.Ml;

/// <summary>
/// ONNX port of <c>sentence-transformers/all-MiniLM-L6-v2</c> for incident
/// similarity search (Step 9 RAG): tokenizes with the shared
/// <see cref="BertWordPieceTokenizer"/> (MiniLM uses the same
/// bert-base-uncased vocab as the phishing model — asserted identical by
/// tools/export_embedding_onnx.py), runs the exported graph, then mean-pools
/// the token embeddings and L2-normalizes, exactly like sentence-transformers.
/// Parity with the Python embeddings is locked in by
/// tests/fixtures/embedding_baseline.json (cosine = 1.000000 on the fixture
/// sentences).
///
/// The model is loaded lazily and thread-safe like
/// <see cref="PhishingClassifier"/>; when the model file is missing the
/// service stays enabled-but-unavailable: it logs one warning and
/// <see cref="EmbedAsync"/> returns null, so the pipeline silently skips RAG.
/// </summary>
public sealed class OnnxEmbeddingService : IEmbeddingService, IDisposable
{
    /// <summary>
    /// sentence-transformers max_seq_length for all-MiniLM-L6-v2 (asserted
    /// against the parity fixture). Inputs are truncated to this many tokens.
    /// </summary>
    public const int MaxTokenCount = 256;

    /// <summary>Embedding dimension of all-MiniLM-L6-v2 (matches the vector(384) column).</summary>
    public const int HiddenSize = 384;

    private readonly ILogger<OnnxEmbeddingService> _logger;
    private readonly Lazy<(InferenceSession Session, BertWordPieceTokenizer Tokenizer)?> _model;
    private readonly object _inferenceLock = new();

    public OnnxEmbeddingService(
        string modelPath,
        string vocabPath,
        bool enabled,
        ILogger<OnnxEmbeddingService> logger)
    {
        _logger = logger;
        Enabled = enabled;
        _model = new Lazy<(InferenceSession, BertWordPieceTokenizer)?>(
            () => Load(modelPath, vocabPath),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public bool Enabled { get; }

    public Task<float[]?> EmbedAsync(string text, CancellationToken cancellationToken = default)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(text))
        {
            return Task.FromResult<float[]?>(null);
        }

        var model = _model.Value; // null after a logged load failure; Lazy caches it
        if (model is null)
        {
            return Task.FromResult<float[]?>(null);
        }

        return Task.Run<float[]?>(() => Embed(model.Value, text), cancellationToken);
    }

    /// <summary>Token ids as fed to the model; internal so the parity test can assert them.</summary>
    internal IReadOnlyList<int> EncodeIds(string text)
    {
        var model = _model.Value
            ?? throw new InvalidOperationException("Embedding model is not available.");
        return model.Tokenizer.Encode(text, MaxTokenCount); // tokenizer is read-only after load
    }

    private (InferenceSession Session, BertWordPieceTokenizer Tokenizer)? Load(string modelPath, string vocabPath)
    {
        if (!File.Exists(modelPath) || !File.Exists(vocabPath))
        {
            _logger.LogWarning(
                "Embedding model not found ({ModelPath}) — incident similarity (RAG) is disabled. " +
                "Run tools/export_embedding_onnx.py in the Python venv to export it.", modelPath);
            return null;
        }

        _logger.LogInformation("Loading embedding ONNX model from {ModelPath}", modelPath);
        var session = new InferenceSession(modelPath);
        var tokenizer = BertWordPieceTokenizer.LoadFromVocabFile(vocabPath);
        _logger.LogInformation(
            "Embedding model loaded; inputs: {Inputs}", string.Join(", ", session.InputMetadata.Keys));
        return (session, tokenizer);
    }

    private float[] Embed((InferenceSession Session, BertWordPieceTokenizer Tokenizer) model, string text)
    {
        var ids = model.Tokenizer.Encode(text, MaxTokenCount);
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
        var available = model.Session.InputMetadata.Keys;
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
            using var results = model.Session.Run(inputs);
            var hidden = (results.FirstOrDefault(r => r.Name == "last_hidden_state") ?? results.First())
                .AsTensor<float>();
            // Batch size is 1 and there is no padding, so the sentence-transformers
            // attention-mask mean pooling reduces to a plain mean over all tokens.
            return MeanPoolAndNormalize(hidden.ToArray(), length, hidden.Dimensions[^1]);
        }
    }

    /// <summary>
    /// Mean-pools <paramref name="tokenCount"/> token embeddings of size
    /// <paramref name="hiddenSize"/> (row-major) and L2-normalizes the result —
    /// the sentence-transformers Pooling + Normalize modules in one step.
    /// </summary>
    internal static float[] MeanPoolAndNormalize(ReadOnlySpan<float> tokenEmbeddings, int tokenCount, int hiddenSize)
    {
        if (tokenEmbeddings.Length < tokenCount * hiddenSize)
        {
            throw new ArgumentException("Not enough values for the given token count and hidden size.",
                nameof(tokenEmbeddings));
        }

        var pooled = new float[hiddenSize];
        for (var token = 0; token < tokenCount; token++)
        {
            for (var dim = 0; dim < hiddenSize; dim++)
            {
                pooled[dim] += tokenEmbeddings[token * hiddenSize + dim];
            }
        }

        double normSquared = 0;
        for (var dim = 0; dim < hiddenSize; dim++)
        {
            pooled[dim] /= tokenCount;
            normSquared += pooled[dim] * (double)pooled[dim];
        }

        var norm = Math.Sqrt(normSquared);
        if (norm > 0)
        {
            for (var dim = 0; dim < hiddenSize; dim++)
            {
                pooled[dim] = (float)(pooled[dim] / norm);
            }
        }

        return pooled;
    }

    public void Dispose()
    {
        if (_model.IsValueCreated)
        {
            _model.Value?.Session.Dispose();
        }
    }
}
