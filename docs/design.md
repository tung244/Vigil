# Vigil — Design Notes

The *how* and *why* behind Vigil's architecture. The README covers what the
system does; this document explains the decisions, mostly by contrasting them
with the original BASTION hackathon build (Python/LangGraph, AWS serverless)
that Vigil is a personal rebuild of. Numbers refer to the decisions table in
`PLAN.md`.

---

## 1. Event-driven ingestion: RabbitMQ instead of BackgroundTasks

The old demo mode ran Tier 1 + LangGraph inside FastAPI `BackgroundTasks` —
the work lived and died with the API process. If the server restarted
mid-analysis, the alert was gone. That was acceptable for a hackathon demo;
it is not a design I would defend in an interview.

Vigil splits ingestion from analysis:

```text
POST /api/jobs  →  store file + insert job row (Queued)  →  publish job id
                                                              │
                                              RabbitMQ queue  ▼
                                              Worker consumes → Tier 1 → Tier 2 → report
```

- The API is a thin, stateless edge: validate, persist, publish, return `202`.
  It can scale and restart independently of the analysis workload.
- The queue is the buffer and the retry boundary. A worker crash leaves the
  message unacked; RabbitMQ redelivers it. The worker is written to tolerate
  that: a redelivered Tier 1 message is detected (`tier1_results` already
  exists) and skipped, and Tier 2 resumes from the job's persisted
  `CurrentStep` instead of starting over.
- RabbitMQ replaces SQS from the AWS design because v1 targets local dev;
  the queue interface (`IJobQueue`) is one small seam if SQS ever comes back.

## 2. Deterministic state machine instead of an LLM supervisor

BASTION's LangGraph supervisor used Gemini to decide which agent runs next,
with hard rules bolted on to stop the worst hallucinations ("iteration 0 with
an email MUST go to the Email Analyst"). That always bothered me: the most
safety-critical decision in the system — *what runs* — was delegated to the
least deterministic component, and then patched with rules to make it behave.

Vigil inverts this. The path is fixed C# (`Tier2StateMachine`):

```text
.eml:  EmailAnalysis → ThreatIntelEnrichment → SynthesisPending → Synthesis
other:                 ThreatIntelEnrichment → SynthesisPending → Synthesis
```

The LLM (Gemini via Semantic Kernel) still does real work — extracting IOCs,
calling tools, drafting the report — but only *inside* a step. It cannot
route, skip threat intel, loop forever, or invent a step. Consequences:

- **No routing hallucination**, by construction. There is nothing to
  hallucinate.
- **Cheaper**: one fewer LLM call per transition, no supervisor prompts.
- **Testable**: the orchestration is pure functions over an enum; unit tests
  cover the whole routing table without touching an LLM.
- **Resumable**: `CurrentStep` is persisted after each state, so a crash
  mid-pipeline resumes at the right state (`SynthesisPending` even lets an
  operator hold a job between enrichment and report generation).

## 3. ONNX in .NET instead of a Python runtime

BASTION's Tier 1 ML ran HuggingFace Transformers in the API process — fine
for a demo, but it pins the whole deployment to a Python + PyTorch stack.
Vigil exports `ealvaradob/bert-finetuned-phishing` to ONNX once
(`tools/export_onnx.py`, run in a dev venv) and serves it from
`Microsoft.ML.OnnxRuntime` inside the .NET worker, with a BERT tokenizer
implemented in C# against `vocab.txt`.

The point is *parity with a different runtime*: same weights, same tokenizer,
same verdicts. Step 5 proved it — `MlParityTests` scores every fixture email
in both the C# classifier and the original Python pipeline and asserts the
probabilities agree within 0.01. The same trick is reused for embeddings
(`minilm.onnx` powers the pgvector RAG), so the production process never
spawns Python. The ~1.25 GB model files are gitignored; CI skips the parity
tests and every ML-free path still works.

## 4. pgvector instead of Pinecone (+ DynamoDB)

The old stack stored job state in DynamoDB and incident embeddings in
Pinecone — two managed services, two bills, neither runnable offline. Vigil
uses one PostgreSQL 16 instance with the pgvector extension for everything:
jobs, tier-1 results, IOCs, threat-intel results, reports, embeddings.

- **Local dev honesty**: `docker compose up -d` gives you the entire data
  plane. No cloud account, no network dependency in a demo.
- **Joins**: "similar past incidents" can filter on verdict, date, or IOC
  overlap in the same query as the vector search — something a standalone
  vector DB pushes back into application code.
- After each report is persisted, its summary is embedded (local MiniLM) into
  `incident_embeddings`; the top-k nearest incidents are injected into the
  synthesis prompt so the LLM can reference prior cases ("matches incident
  X from last week") instead of reasoning in a vacuum.

## 5. Threat intel: the cache is the feature

VirusTotal's free tier allows 4 requests/minute. A burst of 20 alerts with
3 IOCs each is 60 lookups — the API *will* rate-limit you, and a triage
system that falls over under load is worse than none. So the cache is not an
optimization, it is the design:

- Every IOC lookup checks a **24h DB-backed cache** first; repeat incidents
  against the same infrastructure cost zero API calls.
- HttpClient + Polly handle timeouts and retries; `429` and timeouts are
  expected conditions, not exceptions that kill the job.
- When a key is missing or the API is unreachable, lookups fall back to
  **deterministic heuristics** and every result records `fromLiveApi=false`,
  so the report *discloses* that enrichment was heuristic-only. The old
  system asked the LLM to remember to say this in prose; Vigil carries it as
  data, which the validator can actually enforce.

## 6. Evidence discipline and the report validator

The hackathon system had the right instinct — prompt rules telling the LLM
to separate *observed* facts from *assessed* conclusions — plus a post-hoc
Python text-fixer that rewrote wording after the fact. Patching prose with
regexes is fragile; I wanted the discipline in the data model.

Vigil's report is strict JSON: risk score, severity band, summary, MITRE
ATT&CK techniques, recommended actions, and an **evidence trail** where every
claim links to the tool output that supports it. A deterministic
`ReportValidator` then enforces the contract:

- severity must be one of `low/medium/high/critical` and consistent with the
  risk score band;
- MITRE entries must match `T\d{4}(\.\d{3})?` and be non-empty;
- the evidence trail must be non-empty, with a source per claim.

LLM output that breaks the contract is rejected and retried — the validator,
not hope, is the guarantee. IOCs flow through the pipeline as structured
data, so they can't be paraphrased away between extraction and report.

## 7. No-LLM fallback: degrade, don't die

BASTION without a Gemini key returned the string
`"Error generating final synthesis report."` — the worst possible answer
from a triage tool. Vigil treats the LLM as an enhancement layer:

- Without an LLM key, synthesis still runs: a **deterministic rule-based
  report** is generated from tier-1 results, IOCs, and threat-intel data,
  explicitly marked `[generated without LLM]`, and the job completes.
- `.csv`/`.json` log jobs complete end-to-end with no LLM at all.
- The one honest exception: `.eml` jobs *require* the email-analyst step for
  IOC extraction, so they stop at `tier2.email_analysis` by design rather
  than silently producing a content-free report. Failing loudly beats
  succeeding vacuously.

This is also what makes the system cheap to run and test: the entire test
suite (212 tests) passes without any LLM key.

---

## Appendix: one phishing email through the pipeline

Trace of `dataset/mail1.eml` (a bank-themed phishing lure) with every status
transition as actually persisted to `analysis_jobs.current_step`:

1. **Upload.** `POST /api/jobs` with the `.eml`. File stored, job row
   inserted (`Queued`, step `queued`), message published to RabbitMQ,
   API returns `202 { jobId }`.
2. **Tier 1.** Worker consumes the message → `Filtering` /
   `tier1.filtering`. The raw artifact is rule-checked (PII can itself be an
   IOC, so rules see raw text); the PII-scrubbed copy is what every later
   tier and the LLM are allowed to see.
   - Rules fire: `urgent_action_required`, `compliance_pressure`,
     `verify_account`, `suspicious_domain:globalsecure-bank-support.com`,
     `suspicious_domain:globalsecure-bank-verify-login.com`.
   - The ONNX phishing classifier scores the scrubbed subject+body well
     above the 0.7 threshold.
   - Verdict: **Suspicious** (any matched rule *or* ML ≥ threshold).
     `tier1_results` row persisted → `Analyzing` / `tier2.pending`.
3. **Tier 2 — email analysis** (`tier2.email_analysis`). Gemini, via
   Semantic Kernel tool calls, parses headers and body: sender
   `security-alert@globalsecure-bank-support.com`, lure URL
   `http://globalsecure-bank-verify-login.com/session/review`. IOCs are
   extracted as structured rows (sender, domain, URL). The LLM decided
   *which tools to call*; it did not decide to run this step.
4. **Tier 2 — threat intel** (`tier2.threat_intel`). Every IOC goes through
   the cache-first enrichment path: cache hit → done; miss → VirusTotal /
   AbuseIPDB with Polly retry; 429/no-key → heuristic verdict with
   `fromLiveApi=false` recorded.
5. **Synthesis pending** (`tier2.synthesis_pending`). A real checkpoint, not
   a formality: the state machine resumes from here after a crash, and it is
   the natural hook for a future human-approval gate.
6. **Synthesis** (`tier2.synthesis`). The prompt gets the IOCs, enrichment
   results, and the top-k similar past incidents from pgvector. The LLM
   returns strict JSON; `ReportValidator` checks severity band, MITRE
   format, and the evidence trail (retry on violation — no key → the
   deterministic fallback report). Report persisted to `reports`.
7. **Done** (`Done` / `done`). The dashboard, polling `GET /api/jobs/{id}`,
   sees the final state and renders `GET /api/jobs/{id}/report`.

Failure paths are states too, not log lines: `tier1.failed` / `tier2.failed`
persist the exception message on the job, and infrastructure failures (DB
unreachable while saving) propagate so RabbitMQ can redeliver.
