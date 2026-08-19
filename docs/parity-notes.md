# Parity Notes — Step 8 (Synthesis & Report)

Side-by-side comparison of the old BASTION system (Python/LangGraph, read-only
reference in `../bastion/`) against the Vigil rebuild (.NET 9, this repo), per
the Step 8 acceptance criteria: IOCs match, verdicts match, MITRE techniques
non-empty.

## Method & limits

- **No LLM comparison.** Neither system could run its LLM stages: no
  `GEMINI_API_KEY` is available in this environment, so the old
  `synthesis.py` (Gemini) and Vigil's LLM synthesis path were both exercised
  only through fake chat services in tests. What follows compares everything
  *up to* the LLM call and the report *structure*, not LLM prose quality.
- **Inputs:** `../dataset/email.eml` (identical to `tests/fixtures/email.eml`)
  and `../dataset/mail1.eml` (identical to `tests/fixtures/mail1.eml`), a
  phishing lure against a bank.
- **Old system runs:** `bastion/agents/email_analyst/tier1_filter.py::run_static_filter`
  executed in the repo venv with `BASTION_USE_ML_CLASSIFIER=false` (rule-only;
  ML parity is covered separately by Step 5, see below).

## Tier 1 verdict & IOC extraction (rule-based)

Both systems run the same regex families over subject+body, extract
URLs/domains/IPs, header IPs from Received/X-Originating-IP, and flag
suspicious domains.

### `email.eml`

| | Old (Python) | Vigil (.NET) | Match |
|---|---|---|---|
| Decision | SUSPICIOUS | Suspicious | ✅ |
| Static rule score | 11 | 11 | ✅ |
| Matched rules | `urgent_action_required` | `urgent_action_required` | ✅ |
| URLs | `https://training-portal.example/review-session` | same | ✅ |
| Domains | `training-portal.example` | same | ✅ |
| IPs / header IPs | none | none | ✅ |
| Sender | `notifications@secure-review-mail.example` | same (rule IOC, type Email) | ✅ |

Exact parity on this input.

### `mail1.eml`

| | Old (Python) | Vigil (.NET) | Match |
|---|---|---|---|
| Decision | SUSPICIOUS | Suspicious | ✅ |
| Static rule score | 33 | 53 | ⚠️ see below |
| Matched rules | `compliance_pressure`, `suspicious_domain:…verify-login.com`, `suspicious_sender:globalsecure-bank-support.com>`, `urgent_action_required`, `verify_account` | `compliance_pressure`, `suspicious_domain:…verify-login.com`, `suspicious_domain:globalsecure-bank-support.com`, `urgent_action_required`, `verify_account` | ✅ (naming, see below) |
| URLs | `http://globalsecure-bank-verify-login.com/session/review` | same | ✅ |
| Domains | `globalsecure-bank-verify-login.com` | same | ✅ |
| Sender | raw From header | parsed bare address `security-alert@globalsecure-bank-support.com` | ⚠️ see below |

Documented differences:

1. **Sender parsing bug fixed on purpose.** The old system passes the raw
   `From:` header into the sender-domain check, so the rule fires as
   `suspicious_sender:globalsecure-bank-support.com>` (trailing `>` included).
   Vigil parses the bare address first (`EmailRuleChecks.ExtractSenderAddress`)
   and flags the clean domain as `suspicious_domain:<domain>`. Same signal,
   cleaner value; rule id renamed (`suspicious_sender` → `suspicious_domain`).
2. **Rule score 33 vs 53.** The old hybrid score caps rule contribution at 30
   and adds URL/IP/header-IP points. Vigil keeps that shape and adds a +20
   suspicious/lookalike-domain component (both malicious domains here). The
   verdict policy (any matched rule → Suspicious) is identical, so the triage
   decision matches on both inputs.
3. **ML phishing score:** parity between the C# ONNX classifier and the
   original HuggingFace pipeline was established in Step 5
   (`tests/Vigil.IntegrationTests/MlParityTests.cs`, tolerance 0.01 against a
   Python-generated baseline). Not re-run here.

## Threat intel

Not comparable end-to-end (no live API keys on either side). Both systems fall
back to deterministic heuristics without keys; Vigil additionally records
`fromLiveApi=false` per lookup so the report can disclose heuristic-only
enrichment — the "threat intel transparency" rule from the old
`synthesis.py` prompt, now enforced by data instead of prose.

## Report structure

| | Old (`synthesis.py`) | Vigil (Step 8) |
|---|---|---|
| Format | Free-form executive markdown | Strict JSON → `reports` row (risk score, severity, summary markdown, MITRE array, actions array, evidence trail array) |
| Risk score | 0.0–1.0, additive per finding severity | 0.0–10.0, LLM-assigned (validated against severity bands) or deterministic fallback formula |
| MITRE mapping | Embedded in Sigma rule tags inside markdown | Explicit `mitre_techniques` array; validator enforces `T\d{4}(\.\d{3})?` and non-empty |
| Evidence discipline | Prompt rules + `report_validator.py` text post-processing (auto-fix wording, repair pass) | Prompt rules (ported: observed vs assessed, intel transparency, IOC preservation, deprecated-ID list) + deterministic `ReportValidator` on the structured fields (severity band, MITRE format, non-empty evidence trail with per-claim sources) |
| Failure without LLM | Returns the string `"Error generating final synthesis report."` | Deterministic rule-based report marked `[generated without LLM]`; job still completes |
| Persistence | Returned in LangGraph state | `reports` table (jsonb arrays), `GET /api/jobs/{id}/report` |

## What could not be compared, and why

- **LLM synthesis prose** (both systems need a Gemini key): no end-to-end
  narrative comparison. Vigil's LLM path is covered by integration tests with
  a fake chat service asserting the JSON contract, validator retry, and report
  persistence.
- **Old system's final verdict labels** (CRITICAL COMPROMISE / HIGH RISK / …)
  vs Vigil's `low/medium/high/critical` severity bands: the old labels are
  LLM-chosen free text; only Vigil's bands are machine-validated.
