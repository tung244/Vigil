using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Infrastructure.Ml;

namespace Vigil.UnitTests.Ml;

/// <summary>
/// The mean-pooling + L2-normalize math of <see cref="OnnxEmbeddingService"/>
/// (the sentence-transformers Pooling + Normalize modules replicated in C#).
/// </summary>
public class OnnxEmbeddingServiceTests
{
    [Fact]
    public void MeanPool_averages_all_token_embeddings()
    {
        // 2 tokens, hidden size 2: [(3,4), (1,2)] → mean (2,3) → normalize by √13.
        float[] hidden = [3f, 4f, 1f, 2f];

        var embedding = OnnxEmbeddingService.MeanPoolAndNormalize(hidden, tokenCount: 2, hiddenSize: 2);

        var norm = Math.Sqrt(13);
        Assert.Equal(2f / norm, embedding[0], precision: 6);
        Assert.Equal(3f / norm, embedding[1], precision: 6);
    }

    [Fact]
    public void MeanPool_result_is_l2_normalized()
    {
        var random = new Random(42);
        var tokenCount = 17;
        var hiddenSize = 384;
        var hidden = new float[tokenCount * hiddenSize];
        for (var i = 0; i < hidden.Length; i++)
        {
            hidden[i] = (float)(random.NextDouble() * 2 - 1);
        }

        var embedding = OnnxEmbeddingService.MeanPoolAndNormalize(hidden, tokenCount, hiddenSize);

        var norm = Math.Sqrt(embedding.Sum(v => v * (double)v));
        Assert.Equal(1.0, norm, precision: 5);
    }

    [Fact]
    public void MeanPool_all_zero_input_stays_zero_instead_of_dividing_by_zero()
    {
        var embedding = OnnxEmbeddingService.MeanPoolAndNormalize(new float[6], tokenCount: 3, hiddenSize: 2);

        Assert.Equal([0f, 0f], embedding);
    }

    [Fact]
    public async Task EmbedAsync_returns_null_when_disabled_without_touching_the_model_file()
    {
        using var service = new OnnxEmbeddingService(
            "does/not/exist.onnx", "does/not/exist.txt", enabled: false,
            NullLogger<OnnxEmbeddingService>.Instance);

        Assert.False(service.Enabled);
        Assert.Null(await service.EmbedAsync("anything"));
    }

    [Fact]
    public async Task EmbedAsync_returns_null_when_model_file_is_missing()
    {
        using var service = new OnnxEmbeddingService(
            "does/not/exist.onnx", "does/not/exist.txt", enabled: true,
            NullLogger<OnnxEmbeddingService>.Instance);

        Assert.True(service.Enabled); // configured on, but the model is unavailable
        Assert.Null(await service.EmbedAsync("anything"));
    }
}
