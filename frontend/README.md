# Vigil Frontend — SOC Dashboard

Real-time Security Operations Center dashboard built with React, TypeScript, and Vite.

## Tech Stack

- **React 19** + **TypeScript 5.9**
- **Vite 8** (dev server & build)
- **TailwindCSS 3** (styling)
- **React Router** (SPA routing)
- **React Markdown** + **remark-gfm** (report rendering)

## Pages

| Page | Route | Description |
|------|-------|-------------|
| **SOC Dashboard** | `/` | Main analyst workspace — file upload, pipeline status, report viewer |
| **Orchestrator** | `/orchestrator` | Pipeline state viewer (node graph driven by job `currentStep`) |
| **Metrics** | `/metrics` | Aggregated stats over all jobs and reports |

## API Integration

The frontend talks to the Vigil .NET API (`src/Vigil.Api`). All calls live in
`src/services/api.ts`, which adapts the API DTOs into the dashboard's view models.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/jobs` | POST | Upload an `.eml` / `.csv` / `.json` artifact (multipart field `file`) → `202 { jobId }` |
| `/api/jobs` | GET | Paged job list (`?page=&pageSize=`) |
| `/api/jobs/{id}` | GET | Job status + `currentStep` (polled every ~3 s while active) |
| `/api/jobs/{id}/report` | GET | Final report (risk score, MITRE techniques, actions, evidence trail) |
| `/health` | GET | Liveness probe |

The API base URL is configured via `VITE_API_BASE_URL` (see `.env.example`);
it defaults to `http://localhost:5027`.

## Getting Started

```bash
# Install dependencies
npm install

# Start dev server (connects to Vigil.Api on port 5027)
npm run dev

# Build for production
npm run build
```

- **Dev URL:** http://localhost:5173
- **Backend API:** http://localhost:5027 (Vigil.Api must be running; CORS for this origin is enabled in Development)

## Development

```bash
npm run lint       # ESLint checks
npm run build      # Production build (TypeScript check + Vite)
npm run preview    # Preview production build
```
