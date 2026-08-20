import type { Report, TraceEvent, GraphNodeStatus } from '../types';

// ─── Vigil .NET API contract ────────────────────────────────────────────────
// Base URL is configurable via VITE_API_BASE_URL (see .env.example).
// Default matches the Vigil.Api "http" launch profile.
const API_BASE: string = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5027';

export type JobStatus = 'Queued' | 'Filtering' | 'Analyzing' | 'Done' | 'Failed';

export interface JobSummary {
  id: string;
  fileName: string;
  fileType: 'eml' | 'csv' | 'json';
  status: JobStatus;
  currentStep: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  errorMessage: string | null;
  hasReport: boolean;
}

interface JobListResponse {
  items: JobSummary[];
  total: number;
  page: number;
  pageSize: number;
}

export interface EvidenceItem {
  claim: string;
  source: string;
}

export interface ReportResponse {
  jobId: string;
  riskScore: number; // 0–10
  severity: 'low' | 'medium' | 'high' | 'critical';
  summaryMarkdown: string;
  mitreTechniques: string[];
  recommendedActions: string[];
  evidenceTrail: EvidenceItem[];
  createdAt: string;
}

// ─── Raw API calls ──────────────────────────────────────────────────────────

export const fetchJobs = async (page = 1, pageSize = 20): Promise<JobListResponse> => {
  try {
    const res = await fetch(`${API_BASE}/api/jobs?page=${page}&pageSize=${pageSize}`);
    if (!res.ok) throw new Error(`GET /api/jobs failed: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error('API fetch error:', error);
    return { items: [], total: 0, page, pageSize };
  }
};

export const fetchJob = async (id: string): Promise<JobSummary | null> => {
  try {
    const res = await fetch(`${API_BASE}/api/jobs/${id}`);
    if (!res.ok) return null;
    return await res.json();
  } catch (error) {
    console.error('API fetch error:', error);
    return null;
  }
};

/** 200 → report; 404/409 (not finished yet) → null. */
export const fetchJobReport = async (id: string): Promise<ReportResponse | null> => {
  try {
    const res = await fetch(`${API_BASE}/api/jobs/${id}/report`);
    if (!res.ok) return null;
    return await res.json();
  } catch (error) {
    console.error('API fetch error:', error);
    return null;
  }
};

export const uploadFile = async (file: File): Promise<{ message: string; report_id: string } | null> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/api/jobs`, { method: 'POST', body: formData });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new Error(body?.error || `Upload failed: ${res.status}`);
    }
    const data = await res.json(); // 202 { jobId, status }
    return { message: `Job queued (${data.status})`, report_id: data.jobId };
  } catch (error) {
    console.error('API upload error:', error);
    return null;
  }
};

// ─── View-model adapters ────────────────────────────────────────────────────
// The dashboard components were built against the old Python API shapes.
// These adapters translate Vigil jobs/reports into those view models so the
// pages need only minimal changes.

/** Pipeline step order, used to derive per-agent node status. */
const STEP_ORDER = [
  'queued',
  'tier1.filtering',
  'tier1.done',
  'tier2.pending',
  'tier2.email_analysis',
  'tier2.threat_intel',
  'tier2.synthesis_pending',
  'tier2.synthesis',
  'done',
];

const stepIndex = (step: string | null | undefined): number => {
  const i = STEP_ORDER.indexOf(step ?? 'queued');
  return i === -1 ? 0 : i;
};

const toViewStatus = (status: JobStatus): 'running' | 'completed' | 'failed' =>
  status === 'Done' ? 'completed' : status === 'Failed' ? 'failed' : 'running';

const getLatestJob = async (): Promise<JobSummary | null> => {
  const { items } = await fetchJobs(1, 1);
  return items[0] ?? null;
};

/** Job + optional report merged into the legacy Report view model. */
const toViewReport = (job: JobSummary, report: ReportResponse | null): Report => ({
  report_id: job.id,
  event_type: job.fileType === 'eml' ? 'email' : job.fileType,
  status: toViewStatus(job.status),
  risk_score: (report?.riskScore ?? 0) / 10, // legacy UI expects 0–1
  final_report: report?.summaryMarkdown ?? '',
  findings: (report?.evidenceTrail ?? []).map((e) => ({
    agent: e.source,
    finding_type: 'Evidence',
    severity: (report?.severity ?? 'low').toUpperCase() as Report['findings'][number]['severity'],
    description: e.claim,
  })),
  iocs: [], // the Vigil API does not expose IOCs on the report DTO
  messages: [],
  iteration_count: 0,
  error_logs: job.errorMessage ? [job.errorMessage] : [],
  // Synthetic activity log so the per-node expand panels keep working.
  pipeline_logs: buildTraces(job, report).map((t) => ({
    node: traceSourceToNode(t.source),
    action: t.source,
    detail: t.description,
    ts: t.timestamp,
  })),
  timestamp: job.createdAt,
});

export const fetchLatestReport = async (): Promise<Report | null> => {
  const job = await getLatestJob();
  if (!job) return null;
  const report = job.hasReport ? await fetchJobReport(job.id) : null;
  return toViewReport(job, report);
};

const traceSourceToNode = (source: string): string => {
  if (source === 'Upload API') return 'eventbridge';
  if (source === 'Orchestrator') return 'supervisor';
  if (source === 'Synthesis') return 'synthesis';
  if (source === 'System') return 'verdict';
  return 'agents'; // Tier-1 Filter / Email Analyst / Threat Intel
};

/** Derive the reasoning trace from the job's status/currentStep timeline. */
const buildTraces = (job: JobSummary, report: ReportResponse | null): TraceEvent[] => {
  const idx = stepIndex(job.currentStep);
  const created = new Date(job.createdAt);
  const started = job.startedAt ? new Date(job.startedAt) : created;
  const finished = job.finishedAt ? new Date(job.finishedAt) : new Date();

  const traces: TraceEvent[] = [
    {
      id: 'ingest',
      type: 'delegation',
      source: 'Upload API',
      target: 'Job Queue',
      description: `Ingested ${job.fileType.toUpperCase()} artifact: ${job.fileName}`,
      timestamp: created,
    },
  ];

  if (idx >= stepIndex('tier1.filtering')) {
    traces.push({
      id: 'tier1',
      type: 'artifact',
      source: 'Tier-1 Filter',
      target: 'Orchestrator',
      description: 'PII scrubbing, rule checks and ONNX phishing scoring',
      timestamp: started,
    });
  }

  if (idx >= stepIndex('tier2.pending')) {
    traces.push({
      id: 'tier2-escalation',
      type: 'delegation',
      source: 'Orchestrator',
      target: 'Analysis Agents',
      description: 'Artifact suspicious — escalated to the Tier-2 agent pipeline',
      timestamp: started,
    });
  }
  if (idx >= stepIndex('tier2.email_analysis') && job.fileType === 'eml') {
    traces.push({
      id: 'tier2-email',
      type: 'artifact',
      source: 'Email Analyst',
      target: 'Orchestrator',
      description: 'LLM email analysis: header parsing, IOC extraction, phishing verdict',
      timestamp: started,
    });
  }
  if (idx >= stepIndex('tier2.threat_intel')) {
    traces.push({
      id: 'tier2-threat',
      type: 'enrichment',
      source: 'Threat Intel',
      target: 'Orchestrator',
      description: 'IOC enrichment via VirusTotal / AbuseIPDB (DB-backed cache)',
      timestamp: started,
    });
  }
  if (idx >= stepIndex('tier2.synthesis')) {
    traces.push({
      id: 'tier2-synthesis',
      type: 'synthesis',
      source: 'Synthesis',
      target: 'Final Output',
      description: report ? 'Final report generated' : 'Synthesizing final report...',
      timestamp: finished,
    });
  }

  if (job.status === 'Failed') {
    traces.push({
      id: 'failed',
      type: 'error',
      source: 'System',
      target: 'Logger',
      description: job.errorMessage ?? `Job failed at step ${job.currentStep}`,
      timestamp: finished,
    });
  }

  return traces;
};

export const fetchTraces = async (): Promise<TraceEvent[]> => {
  const job = await getLatestJob();
  if (!job) return [];
  const report = job.hasReport ? await fetchJobReport(job.id) : null;
  return buildTraces(job, report);
};

export const fetchAgentLogs = async (agentId: string | null): Promise<any[]> => {
  if (!agentId) return [];
  const job = await getLatestJob();
  if (!job) return [];
  const report = job.hasReport ? await fetchJobReport(job.id) : null;

  const sourceMatch: Record<string, string[]> = {
    supervisor: ['Orchestrator', 'Upload API'],
    forensic: ['Tier-1 Filter'],
    email: ['Email Analyst'],
    threat: ['Threat Intel'],
  };
  const sources = sourceMatch[agentId] ?? [agentId];

  return buildTraces(job, report)
    .filter((t) => sources.includes(t.source))
    .map((t) => ({ ts: t.timestamp, action: t.source, detail: t.description }));
};

/** Map job status/currentStep onto the graph agent nodes. */
export const fetchNodes = async (): Promise<GraphNodeStatus[]> => {
  const job = await getLatestJob();

  const nodes: GraphNodeStatus[] = [
    { id: 'supervisor', name: 'Orchestrator', status: 'idle', type: 'supervisor', icon: 'psychology', message: 'Orchestrator' },
    { id: 'email', name: 'Email Analyst', status: 'idle', type: 'agent', icon: 'mail', message: 'Ready' },
    { id: 'forensic', name: 'Tier-1 Filter', status: 'idle', type: 'agent', icon: 'filter_alt', message: 'Ready' },
    { id: 'threat', name: 'Threat Intel', status: 'idle', type: 'agent', icon: 'public', message: 'Ready' },
  ];
  if (!job) return nodes;

  const done = job.status === 'Done';
  const failed = job.status === 'Failed';
  const active = !done && !failed;
  const idx = stepIndex(job.currentStep);

  return nodes.map((node) => {
    if (node.id === 'supervisor') {
      if (failed) return { ...node, status: 'error', message: job.errorMessage ?? 'Pipeline failed' };
      if (done) return { ...node, status: 'completed', message: 'Synthesis complete' };
      return { ...node, status: 'running', message: job.currentStep ?? 'Queued' };
    }

    // Stage each agent node is responsible for.
    const stageStep =
      node.id === 'forensic' ? 'tier1.filtering' :
      node.id === 'email' ? 'tier2.email_analysis' :
      'tier2.threat_intel';
    const stageIdx = stepIndex(stageStep);

    if (node.id === 'email' && job.fileType !== 'eml') {
      return { ...node, message: 'N/A — non-email artifact' };
    }
    if (active && (job.currentStep === stageStep || (node.id === 'forensic' && job.status === 'Filtering'))) {
      return { ...node, status: 'running', message: 'Analyzing...' };
    }
    if (failed && (job.currentStep ?? '').startsWith(node.id === 'forensic' ? 'tier1' : 'tier2')) {
      // Attribute the failure to the node whose stage was reached last.
      if (idx === 0 || idx >= stageIdx - 1) return { ...node, status: 'error', message: 'Failed' };
    }
    if (done || idx > stageIdx) {
      return { ...node, status: 'completed', message: 'Analysis complete' };
    }
    return node;
  });
};

// ─── Stats endpoints (Vigil.Api) ────────────────────────────────────────────

export interface MitreTechnique {
  techniqueId: string;
  tactic: string;
  count: number;
}

export interface MitreStats {
  techniques: MitreTechnique[];
  tactics: string[]; // already sorted in kill-chain order by the API
}

/** MITRE ATT&CK aggregation for the Metrics heatmap. */
export const fetchMitreStats = async (): Promise<MitreStats | null> => {
  try {
    const res = await fetch(`${API_BASE}/api/stats/mitre`);
    if (!res.ok) throw new Error(`GET /api/stats/mitre failed: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error('API fetch error:', error);
    return null;
  }
};

// ─── /api/stats (server-computed) ───────────────────────────────────────────

export interface ApiStats {
  totalJobs: number;
  totalReports: number;
  jobsByStatus: { queued: number; filtering: number; analyzing: number; done: number; failed: number };
  reportsBySeverity: { low: number; medium: number; high: number; critical: number };
  avgRiskScore: number; // 0–10
  last24hJobs: number;
}

/** Server-side aggregated stats for the dashboard KPI strip. */
export const fetchStatsApi = async (): Promise<ApiStats | null> => {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) throw new Error(`GET /api/stats failed: ${res.status}`);
    return await res.json();
  } catch (error) {
    console.error('API fetch error:', error);
    return null;
  }
};

/** Aggregated stats for the Metrics page, computed from jobs + reports. */
export const fetchStats = async (): Promise<any> => {
  const { items, total } = await fetchJobs(1, 100);
  if (total === 0) return null;

  const reportPairs = await Promise.all(
    items.filter((j) => j.hasReport).map(async (j) => ({ job: j, report: await fetchJobReport(j.id) }))
  );
  const reports = reportPairs.filter((p) => p.report !== null);

  const severity_breakdown = { critical: 0, high: 0, medium: 0, low: 0 };
  const mitre_tactics: Record<string, number> = {};
  const risk_histogram = [0, 0, 0, 0, 0];
  let riskSum = 0;
  let totalFindings = 0;

  for (const { report } of reports) {
    const r = report!;
    severity_breakdown[r.severity] = (severity_breakdown[r.severity] ?? 0) + 1;
    riskSum += r.riskScore;
    totalFindings += r.evidenceTrail.length;
    risk_histogram[Math.min(4, Math.floor(r.riskScore / 2))]++;
    for (const t of r.mitreTechniques) mitre_tactics[t] = (mitre_tactics[t] ?? 0) + 1;
  }

  const emlCount = items.filter((j) => j.fileType === 'eml').length;

  return {
    total_reports: total,
    completed_reports: items.filter((j) => j.status === 'Done').length,
    failed_reports: items.filter((j) => j.status === 'Failed').length,
    total_findings: totalFindings,
    total_iocs: 0, // not exposed by the Vigil report DTO
    avg_risk_score: reports.length > 0 ? riskSum / reports.length / 10 : 0,
    severity_breakdown,
    agent_usage: {
      email_analyst: emlCount,
      forensic_analyst: items.length - emlCount, // Tier-1 log analysis
      threat_intel: reports.length,
    },
    event_type_breakdown: { email: emlCount, cloudtrail: items.length - emlCount },
    risk_histogram,
    mitre_tactics,
    recent_reports: items.map((j) => {
      const pair = reportPairs.find((p) => p.job.id === j.id);
      const findings = (pair?.report?.evidenceTrail ?? []).map((e) => ({
        agent: e.source,
        severity: (pair?.report?.severity ?? 'low').toUpperCase(),
        description: e.claim,
      }));
      return {
        report_id: j.id,
        event_type: j.fileType === 'eml' ? 'email' : 'cloudtrail',
        status: toViewStatus(j.status),
        risk_score: (pair?.report?.riskScore ?? 0) / 10,
        severity: pair?.report?.severity ?? null,
        created_at: j.createdAt,
        finding_count: findings.length,
        findings,
      };
    }),
  };
};

/** Job + report merged for the Metrics report-detail drawer. */
export const fetchReportDetail = async (id: string): Promise<any> => {
  const job = await fetchJob(id);
  if (!job) return { error: `Job ${id} not found.` };
  const report = await fetchJobReport(id);

  return {
    report_id: job.id,
    event_type: job.fileType === 'eml' ? 'email' : job.fileType,
    status: toViewStatus(job.status),
    risk_score: (report?.riskScore ?? 0) / 10,
    severity: report?.severity ?? null,
    created_at: job.createdAt,
    final_report: report?.summaryMarkdown ?? '',
    findings: (report?.evidenceTrail ?? []).map((e) => ({
      agent: e.source,
      severity: (report?.severity ?? 'low').toUpperCase(),
      description: e.claim,
    })),
    iocs: [],
    error_logs: job.errorMessage ? [job.errorMessage] : [],
    mitre_techniques: report?.mitreTechniques ?? [],
    recommended_actions: report?.recommendedActions ?? [],
    processing_time_seconds:
      job.startedAt && job.finishedAt
        ? Math.round(((new Date(job.finishedAt).getTime() - new Date(job.startedAt).getTime()) / 1000) * 100) / 100
        : null,
  };
};
