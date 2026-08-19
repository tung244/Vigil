"""
Step 5 — one-off tooling for the Vigil rebuild.

Two jobs:

1. Baseline: load ``ealvaradob/bert-finetuned-phishing`` from the local HF cache
   (same cache dir as the old Python system, so nothing is re-downloaded) and
   score every ``.eml`` in ``../dataset/``. Results land in
   ``tests/fixtures/ml_baseline.json`` and are the ground truth the C# ONNX
   classifier is compared against (``MlParityTests``).

2. Export: convert the model to ONNX at ``models/phishing.onnx`` and copy
   ``vocab.txt`` next to it. Prefers ``optimum.onnxruntime``; falls back to a
   plain ``torch.onnx.export`` (legacy exporter) if optimum fails.

Text extraction mirrors the C# side exactly so scores are comparable:

  raw .eml
    -> PiiScrubber.Scrub          (port of src/Vigil.Core/Security/PiiScrubber.cs)
    -> EmlParser.Parse            (port of src/Vigil.Core/Tier1/EmlParser.cs)
    -> combine:  f"{subject} [SEP] {body[:512]}"   (same as bastion ml_models.py)
    -> BertTokenizer, truncation max_length=512, no padding

Usage (from the repo venv):
    python tools/export_onnx.py                 # baseline + export
    python tools/export_onnx.py --baseline-only # just regenerate the fixture
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]          # rebuild/
DATASET_DIR = REPO_ROOT.parent / "dataset"               # BASTION_new/dataset
MODELS_DIR = REPO_ROOT / "models"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
BASELINE_JSON = FIXTURES_DIR / "ml_baseline.json"
ONNX_PATH = MODELS_DIR / "phishing.onnx"

MODEL_NAME = "ealvaradob/bert-finetuned-phishing"
MODEL_CACHE_DIR = Path.home() / ".cache" / "bastion" / "models"  # same as bastion/models/ml_models.py

DATASET_FILES = ["email.eml", "ip.eml", "ip2.eml", "ip3.eml", "ip4.eml", "mail1.eml", "mail2.eml"]
THRESHOLD = 0.7

# ---------------------------------------------------------------------------
# Port of Vigil.Core/Security/PiiScrubber.cs — must stay in sync.
# ---------------------------------------------------------------------------

_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")

_PII_RULES = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?<=['\"\s=:])[A-Za-z0-9/+=]{40}(?=['\"\s,}]|$)"), "[REDACTED_AWS_SECRET]"),
    (re.compile(r"\b(?:\d{4}[\s\-]?){3}\d{4}\b"), "[REDACTED_CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
                r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"), "[REDACTED_IP]"),
    (re.compile(r"(?<!\d)(?:\+?\d{1,3}[\s\-])?(?:\(?\d{2,4}\)?[\s\-])?\d{3,4}[\s\-]\d{4}(?!\d)"),
     "[REDACTED_PHONE]"),
]

_AWS_ACCOUNT_ID = re.compile(r"(?:account[_\-\s]?(?:id)?|arn:aws)[:\s\"']*(\d{12})\b", re.IGNORECASE)


def _redact_ipv6(match: re.Match) -> str:
    value = match.group(0)
    try:
        if ":" in value and any(c.isalnum() for c in value) and isinstance(
            ipaddress.ip_address(value), ipaddress.IPv6Address
        ):
            return "[REDACTED_IP]"
    except ValueError:
        pass
    return value


def _redact_account_id(match: re.Match) -> str:
    return match.group(0).replace(match.group(1), "[REDACTED_ACCOUNT_ID]")


def scrub_pii(text: str) -> str:
    """Exact port of PiiScrubber.Scrub (rule order matters)."""
    if not text:
        return text
    result = _IPV6_CANDIDATE.sub(_redact_ipv6, text)
    for pattern, replacement in _PII_RULES:
        result = pattern.sub(replacement, result)
    result = _AWS_ACCOUNT_ID.sub(_redact_account_id, result)
    return result


# ---------------------------------------------------------------------------
# Port of Vigil.Core/Tier1/EmlParser.cs — must stay in sync.
# ---------------------------------------------------------------------------


def parse_eml(raw: str) -> tuple[str, str]:
    """Returns (subject, body). Unfolds headers; splits at the first blank line."""
    text = raw.replace("\r\n", "\n")
    header_end = text.find("\n\n")
    header_block = text[:header_end] if header_end >= 0 else text
    body = text[header_end + 2:] if header_end >= 0 else ""

    headers: list[tuple[str, str]] = []
    current_name: str | None = None
    current_value = ""

    def flush() -> None:
        if current_name is not None:
            headers.append((current_name, current_value))

    for line in header_block.split("\n"):
        if line[:1] in (" ", "\t"):
            if current_name is not None:
                current_value += " " + line.strip()
            continue
        colon = line.find(":")
        if colon <= 0:
            continue
        flush()
        current_name = line[:colon].strip()
        current_value = line[colon + 1:].strip()
    flush()

    subject = next((v for k, v in headers if k.lower() == "subject"), None)
    return subject or "", body


def combine_input(subject: str, body: str) -> str:
    """Same input shape as bastion/models/ml_models.py PhishingClassifier.predict."""
    return f"{subject} [SEP] {body[:512]}"


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def run_baseline() -> list[dict]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
    model.eval()

    print(f"id2label: {model.config.id2label}  (index 1 must be 'phishing')")

    entries = []
    for name in DATASET_FILES:
        raw = (DATASET_DIR / name).read_text(encoding="utf-8")
        subject, body = parse_eml(scrub_pii(raw))
        text = combine_input(subject, body)

        inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            logits = model(**inputs).logits
        score = torch.softmax(logits, dim=1)[0][1].item()

        entries.append({
            "file": name,
            "subject": subject,
            "phishingScore": score,
            "suspicious": score >= THRESHOLD,
            "inputIds": inputs["input_ids"][0].tolist(),
        })
        print(f"  {name:<12} score={score:.6f}  tokens={len(entries[-1]['inputIds'])}"
              f"  verdict={'PHISHING' if score >= THRESHOLD else 'CLEAN'}")

    payload = {
        "model": MODEL_NAME,
        "labels": {str(k): v for k, v in model.config.id2label.items()},
        "phishingLabelIndex": 1,
        "threshold": THRESHOLD,
        "extraction": "scrub_pii(raw) -> parse_eml -> f'{subject} [SEP] {body[:512]}' -> tokenizer(truncation, max_length=512)",
        "entries": entries,
    }
    BASELINE_JSON.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Baseline written to {BASELINE_JSON}")
    return entries


# ---------------------------------------------------------------------------
# ONNX export
# ---------------------------------------------------------------------------


def export_onnx() -> None:
    MODELS_DIR.mkdir(exist_ok=True)
    export_dir = Path(tempfile.mkdtemp(prefix="vigil_onnx_"))

    try:
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification

            print("Exporting via optimum.onnxruntime ...")
            ort_model = ORTModelForSequenceClassification.from_pretrained(
                MODEL_NAME, export=True, cache_dir=str(MODEL_CACHE_DIR)
            )
            ort_model.save_pretrained(str(export_dir))
            produced = export_dir / "model.onnx"
        except Exception as exc:  # noqa: BLE001 — fall back to torch exporter
            print(f"optimum export failed ({exc!r}); falling back to torch.onnx.export")
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
            model = AutoModelForSequenceClassification.from_pretrained(
                MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR)
            ).eval()
            enc = tokenizer("export shape probe", return_tensors="pt")
            produced = export_dir / "model.onnx"
            torch.onnx.export(
                model,
                (enc["input_ids"], enc["attention_mask"], enc["token_type_ids"]),
                str(produced),
                input_names=["input_ids", "attention_mask", "token_type_ids"],
                output_names=["logits"],
                dynamic_axes={
                    "input_ids": {0: "batch", 1: "sequence"},
                    "attention_mask": {0: "batch", 1: "sequence"},
                    "token_type_ids": {0: "batch", 1: "sequence"},
                    "logits": {0: "batch"},
                },
                opset_version=17,
                dynamo=False,
            )

        shutil.copy(produced, ONNX_PATH)

        # Tokenizer vocab for the C# WordPiece tokenizer.
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
        tokenizer.save_pretrained(str(export_dir))
        shutil.copy(export_dir / "vocab.txt", MODELS_DIR / "vocab.txt")

        _validate_onnx()

        size_mb = ONNX_PATH.stat().st_size / (1024 * 1024)
        print(f"ONNX model: {ONNX_PATH} ({size_mb:.1f} MB)")
        print(f"Vocab:      {MODELS_DIR / 'vocab.txt'}")
    finally:
        shutil.rmtree(export_dir, ignore_errors=True)


def _validate_onnx() -> None:
    """Cross-check ONNX logits against the torch model for a probe input."""
    import numpy as np
    import onnxruntime as ort
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, cache_dir=str(MODEL_CACHE_DIR)
    ).eval()
    enc = tokenizer("Urgent: verify your account at once", return_tensors="pt")

    with torch.no_grad():
        torch_logits = model(**enc).logits.numpy()

    session = ort.InferenceSession(str(ONNX_PATH), providers=["CPUExecutionProvider"])
    onnx_inputs = {i.name for i in session.get_inputs()}
    feed = {k: v.numpy() for k, v in enc.items() if k in onnx_inputs}
    onnx_logits = session.run(None, feed)[0]

    diff = float(np.abs(torch_logits - onnx_logits).max())
    print(f"ONNX vs torch max |delta logit|: {diff:.6f}")
    if diff > 1e-3:
        raise RuntimeError(f"ONNX export diverges from torch model (max diff {diff})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-only", action="store_true", help="skip the ONNX export")
    parser.add_argument("--export-only", action="store_true", help="skip the baseline run")
    args = parser.parse_args()

    if not args.export_only:
        run_baseline()
    if not args.baseline_only:
        export_onnx()


if __name__ == "__main__":
    sys.exit(main())
