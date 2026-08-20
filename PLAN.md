# Vigil — Rebuild Plan (Personal .NET Port of BASTION)

> Working name: **Vigil** (rename freely — it is just a string in config).
> Origin: personal rebuild of the BASTION hackathon project (Python/LangGraph)
> as a .NET backend + AI engineering portfolio piece.

## Decisions Locked In

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| 1 | LLM orchestration | **Semantic Kernel** | Standard .NET AI stack, Microsoft-backed, interview-friendly |
| 2 | Agent routing | **Deterministic state machine in C#** | LLM only picks tools within a step; no LLM routing hallucination, cheaper |
| 3 | Database | **PostgreSQL + pgvector** (Docker) | Replaces DynamoDB + Pinecone; one dependency, local dev friendly |
| 4 | Queue | **RabbitMQ** (Docker) | Replaces SQS; job survives worker crash |
| 5 | Tier-1 ML | **ONNX Runtime** running `ealvaradob/bert-finetuned-phishing` exported from HuggingFace | No Python in production runtime; same weights = same verdicts |
| 6 | LSTM UBA | **Dropped**, replaced by statistical rules (z-score / frequency baselines) | Old LSTM weights were never committed; rules are explainable in interviews |
| 7 | Forensic (Athena) | **Dropped for v1**, replaced by a `cloudtrail_logs` table queried via EF Core | No AWS dependency for local dev; note as future work |
| 8 | LLM | **Google Gemini** (same as before) | Free tier, already familiar |
| 9 | Threat intel | VirusTotal v3 + AbuseIPDB v2 with **DB-backed cache** and graceful fallback | VT free tier is 4 req/min — cache is a real requirement |
| 10 | Frontend | **Reuse existing React dashboard**, only rewire `src/services` API client | Zero frontend rewrite cost |
| 11 | Old codebase | **Read-only reference.** Nothing in `bastion/`, `scripts/`, `frontend/` is modified | Demo keeps working no matter what happens here |

## Target Layout

```text
rebuild/
├── PLAN.md                     ← this file
├── Vigil.sln
├── src/
│   ├── Vigil.Api/              ← ASP.NET Core: upload, job status, reports
│   ├── Vigil.Worker/           ← queue consumer, Tier 1 + Tier 2 pipeline
│   ├── Vigil.Core/             ← domain models, state machine, interfaces
│   └── Vigil.Infrastructure/   ← EF Core, RabbitMQ, VT/AbuseIPDB clients, ONNX, SK agents
├── tests/
│   ├── Vigil.UnitTests/
│   └── Vigil.IntegrationTests/
├── docker-compose.yml          ← postgres+pgvector, rabbitmq
└── .github/workflows/ci.yml
```

## Steps

Each step ends with: build green + its acceptance criteria verified. One step per
work session; review before moving on. Commit after each step.

**Status: all steps complete (v1 done).** ✅ 0–10 shipped and verified locally;
✅ 11 (CI & docs) shipped — CI workflow committed but not yet verified against a
real GitHub Actions run (repo has no remote yet).

---

### Step 0 — Repo & skeleton ✅
**Work:** git init; create solution + 4 src projects + 2 test projects; `.gitignore`; README skeleton (honest origin note: "rebuilt from a hackathon team project").
**Acceptance:** `dotnet build` succeeds; `dotnet test` discovers 0 tests and exits 0.
**Verify:** `cd rebuild && dotnet build && dotnet test`

### Step 1 — Local infrastructure ✅
**Work:** `docker-compose.yml` with Postgres 16 + pgvector and RabbitMQ (management UI on 15672); connection strings in `appsettings.Development.json` + user-secrets pattern documented.
**Acceptance:** `docker compose up -d` healthy; can connect to Postgres and open RabbitMQ UI.
**Verify:** `docker compose up -d && docker compose ps` (all `healthy`/`running`)

### Step 2 — Database schema (EF Core) ✅
**Work:** entities + migrations for `analysis_jobs`, `tier1_results`, `iocs`, `threat_intel_results`, `reports`, `incident_embeddings`, `cloudtrail_logs`; pgvector extension enabled in migration.
**Acceptance:** migration applies cleanly on empty DB; `analysis_jobs` round-trips in an integration test.
**Verify:** `dotnet ef database update -p src/Vigil.Infrastructure` then integration test green.

### Step 3 — Upload API ✅
**Work:** `POST /api/jobs` (multipart `.eml`/`.csv`/`.json`, size limit, content validation) → stores file, inserts job row (`Queued`), publishes message to RabbitMQ, returns `202 { jobId }`. `GET /api/jobs/{id}` returns status. `GET /api/jobs` paged list.
**Acceptance:** integration test: upload `dataset/email.eml` → 202 → job row exists → message consumed-proof (or queue depth check).
**Verify:** `dotnet test --filter Upload`

### Step 4 — Worker + Tier 1 (rules & PII) ✅
**Work:** Worker consumes queue; PII scrubber (IP/email/phone/ID → `[REDACTED_*]`) with unit tests incl. edge cases (IPv6, obfuscated URLs); rule checks (SPF/DKIM header parse, lookalike domain); job status transitions `Filtering → …`; statistical anomaly rules for CSV logs (replaces Isolation Forest/LSTM).
**Acceptance:** unit tests for scrubber + rules green; end-to-end: uploaded job reaches `Analyzing` or `Done (Benign)` with `tier1_results` row written.
**Verify:** `dotnet test` + manual upload of `dataset/email.eml`, check DB row.

### Step 5 — ONNX phishing classifier ✅
**Work:** one-off Python script (`tools/export_onnx.py`, run in existing venv) exports `ealvaradob/bert-finetuned-phishing` → `models/phishing.onnx`; C# `PhishingClassifier` loads it via `Microsoft.ML.OnnxRuntime`, tokenizes (BERT tokenizer port or `Microsoft.ML.Tokenizers`), returns score; threshold configurable (default 0.7 to match old README).
**Acceptance:** for every `.eml` in `dataset/`, C# verdict matches the Python pipeline's verdict (run old code once to capture baselines first). Divergence must be explainable and < agreed tolerance.
**Verify:** `dotnet test --filter Onnx` (baseline fixtures committed under `tests/fixtures/`)

### Step 6 — Threat intel clients ✅
**Work:** `VirusTotalClient` + `AbuseIpDbClient` (HttpClient + Polly retry/timeout); 24h DB cache lookup before API call; graceful fallback to heuristic scoring when key missing / 429 / timeout (same contract as old system).
**Acceptance:** unit tests with mocked HttpMessageHandler cover 200/429/timeout/no-key; live smoke test with real key (manual, not CI).
**Verify:** `dotnet test --filter ThreatIntel`

### Step 7 — Agent layer (Semantic Kernel + Gemini) ✅
**Work:** SK kernel setup with Gemini chat connector; plugins: `EmailTools` (parse headers/urls), `ThreatIntelTools` (wraps Step 6), `IncidentTools` (pgvector search, stubbed until Step 9); deterministic state machine drives Email Analyst → Threat Intel → Synthesis; LLM does in-step tool calling only.
**Acceptance:** processing `dataset/email.eml` produces a structured analysis (IOCs extracted, enriched) without any LLM routing decisions; state transitions logged.
**Verify:** integration test with recorded/mocked LLM responses; one live manual run.

### Step 8 — Synthesis & report ✅
**Work:** final report generation (risk score, severity, MITRE ATT&CK mapping, recommended actions, evidence trail linking each claim to a tool output); persisted to `reports`; `GET /api/jobs/{id}/report`.
**Acceptance:** side-by-side comparison vs old system on 2 dataset inputs: IOCs match, verdicts match, MITRE techniques non-empty. Differences documented in `docs/parity-notes.md`.
**Verify:** manual comparison + `dotnet test --filter Report`

### Step 9 — pgvector RAG ✅
**Work:** embed each completed report summary (Gemini embeddings or local MiniLM via ONNX); store in `incident_embeddings`; top-k similar incidents injected into Synthesis prompt.
**Acceptance:** after seeding ≥3 reports, a known-similar input retrieves the expected incident in top-3.
**Verify:** `dotnet test --filter Rag`

### Step 10 — Frontend hookup ✅
**Work:** point existing React `src/services` client at new API base URL; adjust DTO mapping; job status via polling (SignalR = stretch goal, only if time permits).
**Acceptance:** demo scenario 1 (upload `.eml` via dashboard → watch progress → view report) works end-to-end against the .NET backend.
**Verify:** manual run: `dotnet run` API+Worker, `npm run dev` frontend.

### Step 11 — CI & docs ✅
**Work:** GitHub Actions (build + unit tests + integration tests with service containers); README for the new repo (problem, architecture diagram, decisions table, honest origin note, metrics); `docs/design.md` rewritten in own voice.
**Acceptance:** CI green on push; README render check.
**Verify:** push and inspect Actions run.

---

## Explicitly Out of Scope (v1)

- AWS deployment (Lambda/SQS/Athena) — note as future work, optionally re-added later as a deployment doc.
- LSTM autoencoder, Isolation Forest (replaced by Step 4 statistical rules).
- Correlated multi-source batch ingestion (`dataset/a.json` scenario) — add only after Step 10 if desired.
- RLHF analyst feedback loop.

## How We Run This

1. Review/edit this plan — this is the last big-change checkpoint.
2. Say "step N" → I implement exactly that step, run its verify command, report, stop.
3. You review; then "step tiếp" / "step N+1".
4. If a step's acceptance fails and can't be fixed quickly, I stop and report instead of pushing on.
