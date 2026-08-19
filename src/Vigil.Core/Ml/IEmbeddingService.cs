namespace Vigil.Core.Ml;

/// <summary>
/// Embeds text into a dense vector for incident similarity search (pgvector
/// RAG). The production implementation runs
/// <c>sentence-transformers/all-MiniLM-L6-v2</c> (384-dim) as an ONNX model —
/// no Python, no external API key. Implementations are expected to be
/// thread-safe singletons and to degrade silently (return null) when the
/// model is unavailable, so the pipeline keeps working without embeddings.
/// </summary>
public interface IEmbeddingService
{
    /// <summary>When false, callers skip embedding and similarity retrieval entirely.</summary>
    bool Enabled { get; }

    /// <summary>
    /// Returns the L2-normalized embedding for <paramref name="text"/>, or null
    /// when the model file is missing/unloadable (a warning is logged once).
    /// </summary>
    Task<float[]?> EmbedAsync(string text, CancellationToken cancellationToken = default);
}
