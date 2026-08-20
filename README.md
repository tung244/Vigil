# Vigil

AI-assisted security alert triage — .NET 9, ASP.NET Core, Semantic Kernel, PostgreSQL + pgvector, RabbitMQ, ONNX Runtime.

> **Origin:** Vigil is my personal, ground-up rebuild of **BASTION**, a team
> hackathon project (Python/LangGraph, AWS serverless) I worked on. The domain
> and problem framing come from that project; every line of code, the
> architecture, and the engineering decisions here are my own. The original
> repo stays untouched as a read-only reference. See
> [`docs/parity-notes.md`](docs/parity-notes.md) for a measured comparison and
> [`docs/design.md`](docs/design.md) for the design rationale.

## The problem

SOC analysts drown in false positives. Manually investigating one alert —
reading headers, extracting IOCs, pivoting to threat intel, writing it up —
takes ~30 minutes, and most alerts are benign. Vigil automates the boring 95%:
ingest a suspicious artifact (`.eml`, `.csv`, `.json`), filter it with cheap
deterministic checks first, and only spend LLM tokens on what survives — then
hand the analyst an explainable, evidence-backed incident report instead of a
raw alert.

## Features

- **Two-tier pipeline.** Tier 1 (PII scrubbing, static rules, SPF/DKIM header
  checks, lookalike-domain detection, an ONNX phishing classifier) runs with
  zero LLM cost and closes benign jobs outright. Only suspicious artifacts
  reach Tier 2.
- **Deterministic agent orchestration.** Tier 2 is a C# state machine, not an
  LLM supervisor. The LLM (Gemini via Semantic Kernel) only does in-step tool
  calling — it can never hallucinate a route.
- **Threat intel with a real cache.** VirusTotal v3 + AbuseIPDB v2 behind a
  24h DB-backed cache (VT free tier is 4 req/min — the cache is a requirement,
  not a nicety), with Polly retry/timeout and a deterministic heuristic
  fallback when keys are missing or the API is down.
- **Evidence discipline.** Every claim in the final report links back to a
  tool output; a `ReportValidator` enforces severity bands, MITRE ATT&CK
  technique format, and a non-empty evidence trail — and rejects LLM output
  that breaks the contract.
- **No-LLM fallback.** Without a Gemini key, `.csv`/`.json` jobs still
  complete end-to-end with a deterministic rule-based report (marked
  `[generated without LLM]`). The system degrades, it doesn't die.
- **pgvector RAG.** Completed reports are embedded (local MiniLM via ONNX) and
  similar past incidents are injected into the synthesis prompt.
- **React dashboard.** Upload artifacts, poll job progress, read the report.

## Architecture

```text
┌──────────────┐   HTTP    ┌────────────┐  publish  ┌──────────┐  consume  ┌───────────────┐
│ React        │──────────▶│ Vigil.Api  │──────────▶│ RabbitMQ │──────────▶│ Vigil.Worker  │
│ dashboard    │◀──────────│ (upload,   │           │  queue   │           │               │
│ (Vite)       │  status / │  status,   │           └──────────┘           │  Tier 1: PII  │
└──────────────┘  report   │  report)   │                                  │  scrub, rules,│
                           └─────┬──────┘                                  │  ONNX phishing│
                                 │                                         │  classifier   │
                                 │                                         └──────┬────────┘
                                 │                                                │ suspicious
                                 ▼                                                ▼
                        ┌──────────────────┐   jobs / tier1 / iocs /    ┌───────────────────┐
                        │ PostgreSQL       │◀── reports / embeddings ──│  Tier 2: state    │
                        │  + pgvector      │                            │  machine (SK +    │
                        └──────────────────┘                            │  Gemini): email   │
                                 ▲                                      │  analysis → threat│
                                 │        VT / AbuseIPDB (cached)       │  intel → synthesis│
                                 └──────────────────────────────────────│  → report + RAG   │
                                                                        └───────────────────┘
```

Job progress is observable end-to-end via `CurrentStep`:
`queued → tier1.filtering → tier2.pending → tier2.email_analysis →
tier2.threat_intel → tier2.synthesis_pending → tier2.synthesis → done`
(non-email artifacts skip the email analyst; benign jobs finish at
`tier1.done`).

## Key decisions

| Decision | Choice | Why |
|---|---|---|
| Agent routing | Deterministic C# state machine | No LLM routing hallucination, cheaper, testable; LLM only picks tools within a step |
| Tier-1 ML | ONNX Runtime (`ealvaradob/bert-finetuned-phishing`, exported from HuggingFace) | Same weights = same verdicts as the Python original; no Python in the production runtime |
| Database | PostgreSQL + pgvector | One dependency replaces DynamoDB + Pinecone; local-dev friendly |
| Queue | RabbitMQ | Replaces SQS; a job survives a worker crash |
| Threat intel | VT + AbuseIPDB behind a DB cache, heuristic fallback | Free-tier rate limits make the cache mandatory; missing keys degrade gracefully |
| UBA anomaly detection | Statistical rules (z-score / frequency baselines) | The old LSTM weights were never committed; rules are explainable |
| Forensic (Athena) | Dropped for v1 (`cloudtrail_logs` table instead) | No AWS dependency for local dev; AWS redeploy is future work |

The full per-step build plan with acceptance criteria is in [`PLAN.md`](PLAN.md).

## Tech stack

- **Backend:** .NET 9, ASP.NET Core (API), generic host (Worker), EF Core 9 + Npgsql, Semantic Kernel + Google Gemini, Microsoft.ML.OnnxRuntime, RabbitMQ.Client, Polly
- **Data:** PostgreSQL 16 + pgvector, RabbitMQ 3
- **Frontend:** React 19, Vite, TypeScript, Tailwind CSS
- **Tests:** xUnit, Microsoft.AspNetCore.Mvc.Testing, Xunit.SkippableFact

## Run it locally

Prerequisites: .NET 9 SDK, Node 20+, Docker.

```bash
# 1. Infrastructure (Postgres + pgvector on :55432, RabbitMQ on :5672 / UI on :15672)
docker compose up -d

# 2. Database schema
dotnet tool restore
dotnet ef database update --project src/Vigil.Infrastructure --startup-project src/Vigil.Api

# 3. API — http://localhost:5027
dotnet run --project src/Vigil.Api

# 4. Worker (queue consumer, Tier 1 + Tier 2 pipeline)
dotnet run --project src/Vigil.Worker

# 5. Frontend — http://localhost:5173
cd frontend
npm install
npm run dev
```

The dashboard reads the API base URL from `VITE_API_BASE_URL` (see
`frontend/.env.example`); it defaults to `http://localhost:5027`.

**Optional keys**: `Llm:ApiKey` (Gemini), `ThreatIntel:VirusTotalApiKey`,
`ThreatIntel:AbuseIpDbApiKey`. All three are optional — missing keys trigger the
documented fallbacks, not crashes. Note: without a Gemini key, `.eml` jobs stop
at `tier2.email_analysis` by design, while `.csv`/`.json` jobs complete
end-to-end.

**Do not put keys in `appsettings.json`** (it is committed). Use user-secrets:

```bash
cd src/Vigil.Worker
dotnet user-secrets set "Llm:ApiKey" "<your-gemini-key>"
dotnet user-secrets set "ThreatIntel:VirusTotalApiKey" "<your-vt-key>"
dotnet user-secrets set "ThreatIntel:AbuseIpDbApiKey" "<your-abuseipdb-key>"
```

**ONNX models** (`models/phishing.onnx`, `models/minilm.onnx`) are gitignored
(~1.25 GB). Regenerate them with `tools/export_onnx.py`; without them, ML
scoring and embeddings are disabled and the rule-based path still works.

## Testing

212 tests total: **181 unit** + **31 integration**.

```bash
dotnet build          # 0 warnings, 0 errors
dotnet test           # unit + integration
```

Integration tests need the docker-compose stack running (Postgres on `:55432`,
RabbitMQ on `:5672`). Connection strings default to the local stack and can be
overridden via the `VIGIL_TEST_POSTGRES` / `VIGIL_TEST_RABBITMQ` environment
variables — CI uses exactly that mechanism.

The model-dependent tests (`MlParityTests`, `EmbeddingParityTests`,
`RagRetrievalTests`) use `SkippableFact` and skip when `models/*.onnx` is
absent — that is the expected behavior on CI, where the gitignored model
files don't exist.

CI (`.github/workflows/ci.yml`) runs both jobs on every push and PR: backend
(.NET build + tests against postgres/rabbitmq service containers) and
frontend (`npm ci` + `npm run build`).

## Roadmap / future work

- **AWS deployment** — Lambda + SQS + Athena variant of the original BASTION
  topology, as a deployment target next to docker-compose.
- **Live LLM runs in CI** — recorded/mocked LLM responses are covered; a
  scheduled live Gemini smoke test with a secret key is not wired up yet.
- **SignalR job progress** — the dashboard currently polls; pushing
  `CurrentStep` transitions over SignalR is the natural upgrade.
- **Sigma rule export** — turn synthesized reports into detection rules for
  legacy SIEMs (carried over from the original project's roadmap).
