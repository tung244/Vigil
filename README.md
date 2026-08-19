# Vigil

AI-assisted security alert triage backend — .NET 9, ASP.NET Core, Semantic Kernel, PostgreSQL.

> **Origin:** Vigil is a personal, ground-up rebuild of **BASTION**, a team hackathon
> project (Python/LangGraph) I worked on. The domain and problem framing come from
> that project; every line of code, the architecture, and the engineering decisions
> here are my own. See `docs/parity-notes.md` (from Step 8) for a comparison.

## Problem

SOC analysts drown in false positives; manually investigating a single alert takes
~30 minutes. Vigil ingests suspicious artifacts (`.eml`, `.csv`, `.json`), filters
benign events with cheap Tier-1 checks (rules + ONNX ML model, no LLM cost), then
runs an LLM agent pipeline (Semantic Kernel + Gemini) with threat-intel enrichment
(VirusTotal, AbuseIPDB) to produce an explainable incident report.

## Architecture (v1)

```text
React dashboard ──HTTP──> Vigil.Api ──publish──> RabbitMQ ──consume──> Vigil.Worker
                               │                                        │
                               └────────────── PostgreSQL (+pgvector) ◄─┘
                                                jobs / tier1 / iocs / reports
```

Worker pipeline: **Tier 1** (PII scrub → rule checks → ONNX phishing classifier)
→ if suspicious: **Tier 2** (deterministic state machine; LLM tool-calling within
each step: email analysis → threat intel → synthesis) → report.

Full rationale and the per-step build plan: [`PLAN.md`](PLAN.md).

## Layout

```text
src/
  Vigil.Api/             ASP.NET Core — upload, job status, reports
  Vigil.Worker/          RabbitMQ consumer, Tier 1 + Tier 2 pipeline
  Vigil.Core/            Domain models, state machine, interfaces
  Vigil.Infrastructure/  EF Core, RabbitMQ, threat-intel clients, ONNX, SK agents
tests/
  Vigil.UnitTests/
  Vigil.IntegrationTests/
```

## Status

Step 0 complete (solution skeleton). See `PLAN.md` for the roadmap.

## Build & Test

```bash
dotnet build
dotnet test
```
