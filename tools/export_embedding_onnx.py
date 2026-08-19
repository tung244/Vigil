"""
Step 9 — one-off tooling for the Vigil rebuild.

Exports ``sentence-transformers/all-MiniLM-L6-v2`` to ONNX at
``models/minilm.onnx`` and captures the parity fixture the C#
``OnnxEmbeddingService`` is tested against
(``tests/fixtures/embedding_baseline.json``).

Why a manual mean-pooling step: MiniLM's ONNX graph emits per-token hidden
states; sentence-transformers turns those into a sentence vector with
mean-pooling over the attention mask followed by L2 normalization. The C#
service replicates that math, so this script validates the ONNX output +
manual pooling against the real ``SentenceTransformer.encode`` and writes the
expected vectors (and the tokenizer's input ids) into the fixture.

The model uses the bert-base-uncased vocab — asserted identical to the
phishing model's ``models/vocab.txt`` when that file exists, so the C# side
reuses ``BertWordPieceTokenizer`` with the same vocab file.

Usage (from the repo venv, python -m pip … — pip.exe is broken):
    python tools/export_embedding_onnx.py
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]          # rebuild/
MODELS_DIR = REPO_ROOT / "models"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
ONNX_PATH = MODELS_DIR / "minilm.onnx"
FIXTURE_JSON = FIXTURES_DIR / "embedding_baseline.json"
EXISTING_VOCAB = MODELS_DIR / "vocab.txt"

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_CACHE_DIR = Path.home() / ".cache" / "bastion" / "models"  # same as tools/export_onnx.py

# Topics mirror RagRetrievalTests; pairs are the cross-sentence similarity checks.
SENTENCES = [
    "Credential-harvesting phishing email impersonating a bank, urging the victim to verify their account through a lookalike login portal.",
    "Brute-force login attack: hundreds of failed SSH password attempts against the admin account from a single external IP address.",
    "Malware infection beaconing to a command-and-control server with periodic HTTP callbacks to a known botnet domain.",
    "Suspicious email asking employees to enter their banking credentials on a fake verification page.",
    "Routine monthly patching report; no anomalies detected in authentication logs.",
]

PAIRS = [(0, 3), (0, 1), (1, 2), (0, 4)]


def export_onnx() -> None:
    from optimum.onnxruntime import ORTModelForFeatureExtraction

    MODELS_DIR.mkdir(exist_ok=True)
    export_dir = Path(tempfile.mkdtemp(prefix="vigil_minilm_"))
    try:
        print("Exporting via optimum.onnxruntime (feature extraction) ...")
        ort_model = ORTModelForFeatureExtraction.from_pretrained(
            MODEL_NAME, export=True, cache_dir=str(MODEL_CACHE_DIR)
        )
        ort_model.save_pretrained(str(export_dir))
        shutil.copy(export_dir / "model.onnx", ONNX_PATH)
    finally:
        shutil.rmtree(export_dir, ignore_errors=True)

    size_mb = ONNX_PATH.stat().st_size / (1024 * 1024)
    print(f"ONNX model: {ONNX_PATH} ({size_mb:.1f} MB)")


def check_vocab() -> None:
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
    export_dir = Path(tempfile.mkdtemp(prefix="vigil_minilm_vocab_"))
    try:
        tokenizer.save_pretrained(str(export_dir))
        minilm_vocab = (export_dir / "vocab.txt").read_text(encoding="utf-8")
        if EXISTING_VOCAB.exists():
            if EXISTING_VOCAB.read_text(encoding="utf-8") == minilm_vocab:
                print("vocab.txt: identical to the phishing model's vocab — C# reuses models/vocab.txt")
            else:
                target = MODELS_DIR / "minilm_vocab.txt"
                target.write_text(minilm_vocab, encoding="utf-8")
                print(f"WARNING: MiniLM vocab differs from models/vocab.txt; wrote {target}")
        else:
            EXISTING_VOCAB.write_text(minilm_vocab, encoding="utf-8")
            print(f"vocab.txt: written to {EXISTING_VOCAB}")
    finally:
        shutil.rmtree(export_dir, ignore_errors=True)


def build_fixture_and_validate() -> None:
    import numpy as np
    import onnxruntime as ort
    from sentence_transformers import SentenceTransformer

    st = SentenceTransformer(MODEL_NAME, cache_folder=str(MODEL_CACHE_DIR))
    max_tokens = st.max_seq_length
    print(f"sentence-transformers max_seq_length = {max_tokens}, dim = {st.get_sentence_embedding_dimension()}")

    # Ground truth: real sentence-transformers embeddings.
    st_embeddings = st.encode(SENTENCES, convert_to_numpy=True, normalize_embeddings=True)

    # Token ids exactly as sentence-transformers produces them, but batched
    # per sentence so no padding [PAD] ids leak in — the C# side tokenizes a
    # single unpadded sequence.
    input_ids = [st.tokenize([s])["input_ids"][0].tolist() for s in SENTENCES]

    # ONNX + manual mean-pooling + L2 normalize, replicating the C# service.
    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    onnx_input_names = {i.name for i in session.get_inputs()}
    print(f"ONNX inputs: {sorted(onnx_input_names)}")

    # Pad to a rectangular batch for the ONNX validation feed.
    max_len = max(len(row) for row in input_ids)
    ids = np.array([row + [0] * (max_len - len(row)) for row in input_ids], dtype=np.int64)
    mask = np.array([[1] * len(row) + [0] * (max_len - len(row)) for row in input_ids], dtype=np.int64)
    feed = {"input_ids": ids, "attention_mask": mask}
    if "token_type_ids" in onnx_input_names:
        feed["token_type_ids"] = np.zeros_like(ids)
    hidden = session.run(None, feed)[0]  # [batch, seq, 384]

    mask_f = mask.astype(np.float32)
    pooled = (hidden * mask_f[..., None]).sum(axis=1) / np.clip(mask_f.sum(axis=1, keepdims=True), 1e-9, None)
    normed = pooled / np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12, None)

    print("\nParity: ONNX+manual pooling vs sentence-transformers")
    worst = 0.0
    for i, sentence in enumerate(SENTENCES):
        sim = float(np.dot(normed[i], st_embeddings[i]))
        worst = max(worst, 1.0 - sim)
        print(f"  [{i}] cosine={sim:.6f}  {sentence[:60]}...")
        if sim < 0.999:
            raise RuntimeError(f"ONNX embedding diverges from sentence-transformers (cosine {sim})")
    print(f"worst 1-cosine: {worst:.2e}")

    def cos(a: np.ndarray, b: np.ndarray) -> float:
        return float(np.dot(a, b))

    pairs = [{"a": a, "b": b, "cosine": cos(st_embeddings[a], st_embeddings[b])} for a, b in PAIRS]
    print("\nPairwise cosine similarities (sentence-transformers, ground truth):")
    for pair in pairs:
        print(f"  ({pair['a']},{pair['b']}): {pair['cosine']:.6f}")

    FIXTURES_DIR.mkdir(exist_ok=True)
    payload = {
        "model": MODEL_NAME,
        "maxTokens": max_tokens,
        "dimensions": int(st.get_sentence_embedding_dimension()),
        "pooling": "mean over attention mask, then L2 normalize (sentence-transformers default for this model)",
        "entries": [
            {"text": text, "inputIds": ids_row, "embedding": emb.tolist()}
            for text, ids_row, emb in zip(SENTENCES, input_ids, st_embeddings)
        ],
        "pairs": pairs,
    }
    FIXTURE_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nFixture written to {FIXTURE_JSON}")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-only", action="store_true",
                        help="skip the ONNX export; only regenerate the fixture from the existing model file")
    args = parser.parse_args()

    if not args.fixture_only:
        export_onnx()
        check_vocab()
    build_fixture_and_validate()


if __name__ == "__main__":
    main()
