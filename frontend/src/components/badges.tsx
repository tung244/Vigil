import type { ReactNode } from 'react';

// ─── SOC badge system (Wazuh-style) ─────────────────────────────────────────
// Shared visual language for severity, pipeline status, and machine data.

export type Severity = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_CLASSES: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/40',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  low: 'bg-sky-500/15 text-sky-400 border-sky-500/40',
};

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-sky-400',
};

/** Normalize free-form severity text (e.g. "CRITICAL", "High") to a Severity. */
export const normalizeSeverity = (value: string | null | undefined): Severity => {
  const v = (value ?? '').toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium') return v;
  return 'low';
};

/** Derive a severity bucket from a 0–1 (or 0–100) risk score. */
export const severityFromRisk = (risk: number): Severity => {
  const pct = risk <= 1 ? risk * 100 : risk;
  if (pct >= 80) return 'critical';
  if (pct >= 60) return 'high';
  if (pct >= 40) return 'medium';
  return 'low';
};

export const SeverityBadge = ({ severity, className = '' }: { severity: Severity | string; className?: string }) => {
  const sev = normalizeSeverity(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${SEVERITY_CLASSES[sev]} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${SEVERITY_DOT[sev]}`}></span>
      {sev}
    </span>
  );
};

// ─── Pipeline / job status ──────────────────────────────────────────────────

type StatusTone = 'ok' | 'error' | 'running' | 'queued' | 'neutral';

const STATUS_TONE: Record<string, StatusTone> = {
  done: 'ok',
  completed: 'ok',
  failed: 'error',
  error: 'error',
  analyzing: 'running',
  filtering: 'running',
  running: 'running',
  queued: 'queued',
  pending: 'queued',
};

const TONE_CLASSES: Record<StatusTone, string> = {
  ok: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  error: 'bg-red-500/15 text-red-400 border-red-500/40',
  running: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  queued: 'bg-slate-500/15 text-slate-400 border-slate-500/40',
  neutral: 'bg-slate-500/15 text-slate-400 border-slate-500/40',
};

export const StatusBadge = ({ status, className = '' }: { status: string; className?: string }) => {
  const tone = STATUS_TONE[status.toLowerCase()] ?? 'neutral';
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${TONE_CLASSES[tone]} ${className}`}
    >
      {tone === 'running' && (
        <span className="relative flex h-1.5 w-1.5">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-amber-400"></span>
        </span>
      )}
      {status}
    </span>
  );
};

// ─── Monospace machine data ─────────────────────────────────────────────────

/** Monospace inline text for IOCs, IPs, hashes, report IDs. */
export const Mono = ({ children, className = '' }: { children: ReactNode; className?: string }) => (
  <span className={`font-mono text-[11px] tracking-tight text-slate-600 dark:text-slate-300 ${className}`}>{children}</span>
);
