using Microsoft.Extensions.Logging.Abstractions;
using Vigil.Infrastructure.Ml;
using Xunit;

namespace Vigil.UnitTests.Ml;

/// <summary>
/// Unit tests for the parts of <see cref="PhishingClassifier"/> that do not
/// need the ONNX model file: softmax scoring, the disabled-mode guard and the
/// property surface. Token-id and score parity with the HuggingFace model are
/// covered by the integration tests (MlParityTests).
/// </summary>
public class PhishingClassifierTests
{
    [Fact]
    public void Softmax_returns_probability_of_phishing_logit()
    {
        // logits [benign=0, phishing=0] -> 0.5
        Assert.Equal(0.5, PhishingClassifier.SoftmaxPhishingProbability([0f, 0f]), 6);

        // logits [0, 2] -> e^2 / (1 + e^2) ≈ 0.8808
        Assert.Equal(0.880797, PhishingClassifier.SoftmaxPhishingProbability([0f, 2f]), 4);
    }

    [Fact]
    public void Softmax_is_numerically_stable_for_extreme_logits()
    {
        // Would overflow a naive exp() implementation; max-subtraction keeps it finite.
        var score = PhishingClassifier.SoftmaxPhishingProbability([-1000f, 1000f]);
        Assert.Equal(1.0, score, 10);
    }

    [Fact]
    public void Disabled_classifier_rejects_classify_calls()
    {
        // Paths are never touched: model loading is lazy and the guard fires first.
        using var classifier = new PhishingClassifier(
            "missing.onnx", "missing-vocab.txt", threshold: 0.7, enabled: false,
            NullLogger<PhishingClassifier>.Instance);

        Assert.False(classifier.Enabled);
        Assert.Throws<InvalidOperationException>(() => classifier.Classify("subject", "body"));
    }

    [Fact]
    public void Threshold_and_enabled_reflect_constructor_arguments()
    {
        using var classifier = new PhishingClassifier(
            "missing.onnx", "missing-vocab.txt", threshold: 0.42, enabled: true,
            NullLogger<PhishingClassifier>.Instance);

        Assert.True(classifier.Enabled);
        Assert.Equal(0.42, classifier.Threshold);
    }
}
