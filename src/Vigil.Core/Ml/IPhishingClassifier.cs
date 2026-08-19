namespace Vigil.Core.Ml;

/// <summary>
/// Scores email text with the phishing classifier
/// (<c>ealvaradob/bert-finetuned-phishing</c>, ONNX export). Replaces the
/// lazy-loaded Python singleton from the old system; implementations are
/// expected to be thread-safe singletons.
/// </summary>
public interface IPhishingClassifier
{
    /// <summary>When false, Tier 1 skips ML scoring and stores a null score.</summary>
    bool Enabled { get; }

    /// <summary>Score at or above which the email counts as phishing (default 0.7).</summary>
    double Threshold { get; }

    /// <summary>
    /// Returns the phishing probability in [0, 1] for the given email
    /// (softmax of the "phishing" logit; label index 1 per the model config).
    /// </summary>
    double Classify(string? subject, string body);
}
