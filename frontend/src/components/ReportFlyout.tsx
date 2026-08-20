import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { SeverityBadge, StatusBadge, Mono, normalizeSeverity, severityFromRisk } from './badges';
import { fetchReportDetail } from '../services/api';
import type { JobSummary } from '../services/api';

// ─── Shared report flyout (Wazuh-style, tabbed) ─────────────────────────────
// Used by both the Metrics alerts table and the SOCDashboard live alert feed.
// Fetches the merged job+report detail itself; for jobs without a report yet
// the Overview tab shows the live pipeline state instead.

interface ReportFlyoutProps {
  reportId: string;
  /** Optional job summary — enables the "pipeline in progress" overview state. */
  job?: JobSummary | null;
  onClose: () => void;
}

export const ReportFlyout = ({ reportId, job, onClose }: ReportFlyoutProps) => {
  const [reportDetail, setReportDetail] = useState<any>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'json'>('overview');
  const [blockedIPs, setBlockedIPs] = useState<Set<string>>(new Set());
  const [blockToast, setBlockToast] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setReportDetail(null);
    setActiveTab('overview');
    fetchReportDetail(reportId).then((d) => { if (!cancelled) setReportDetail(d); });
    return () => { cancelled = true; };
  }, [reportId]);

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm"></div>
      <div className="relative w-full max-w-2xl bg-white dark:bg-slate-900 shadow-2xl overflow-y-auto animate-slide-in" onClick={(e) => e.stopPropagation()}>
        <div className="sticky top-0 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 z-10">
          <div className="p-4 pb-2 flex justify-between items-center">
            <div>
              <h3 className="font-black text-lg">Report Detail</h3>
              <Mono className="font-bold text-primary">{reportId}</Mono>
              {job && (
                <div className="flex items-center gap-2 mt-1">
                  <Mono className="text-slate-500">{job.fileName}</Mono>
                  <StatusBadge status={job.status} />
                </div>
              )}
            </div>
            <button onClick={onClose} className="size-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors">
              <span className="material-symbols-outlined text-sm">close</span>
            </button>
          </div>
          {/* Tabs */}
          <div className="px-4 flex gap-1">
            {([
              { id: 'overview', label: 'Overview', icon: 'dashboard' },
              { id: 'evidence', label: 'Evidence', icon: 'policy' },
              { id: 'json', label: 'Raw JSON', icon: 'data_object' },
            ] as const).map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-bold uppercase tracking-wider border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary text-primary'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                }`}
              >
                <span className="material-symbols-outlined text-sm">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {!reportDetail ? (
          <div className="p-8 text-center"><span className="material-symbols-outlined text-primary text-3xl animate-spin">autorenew</span></div>
        ) : reportDetail.error ? (
          <div className="p-6 text-red-500 text-sm">{reportDetail.error}</div>
        ) : (
          <div className="p-4 space-y-4">
            {/* ── Fallback extraction for tier1 + timing ── */}
            {(() => {
              // Extract tier1 from findings evidence if not set by backend
              if (!reportDetail.tier1_filter && reportDetail.findings?.length > 0) {
                for (const f of reportDetail.findings) {
                  if (f.evidence?.tier1_result) {
                    reportDetail.tier1_filter = f.evidence.tier1_result;
                    break;
                  }
                }
                // Still no tier1? Build from risk score
                if (!reportDetail.tier1_filter) {
                  const risk = reportDetail.risk_score || 0;
                  reportDetail.tier1_filter = {
                    decision: risk > 0.4 ? 'SUSPICIOUS' : 'CLEAN',
                    matched_rules: reportDetail.findings
                      .filter((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH')
                      .map((f: any) => f.mitre_tactic || f.finding_type)
                      .filter(Boolean),
                    static_risk_score: Math.round(risk * 100),
                    model: reportDetail.event_type === 'email' ? 'DistilBERT (ealvaradob/bert-finetuned-phishing)' : 'LSTM Autoencoder + Isolation Forest',
                  };
                }
                // Add model if missing
                if (reportDetail.tier1_filter && !reportDetail.tier1_filter.model) {
                  reportDetail.tier1_filter.model = reportDetail.event_type === 'email'
                    ? 'DistilBERT (ealvaradob/bert-finetuned-phishing)'
                    : 'LSTM Autoencoder + Isolation Forest';
                }
              }
              // Estimate processing time from pipeline_logs if not set
              if (!reportDetail.processing_time_seconds && reportDetail.pipeline_logs?.length > 1) {
                const logs = reportDetail.pipeline_logs;
                const first = new Date(logs[0].ts).getTime();
                const last = new Date(logs[logs.length - 1].ts).getTime();
                if (first && last && last > first) {
                  reportDetail.processing_time_seconds = Math.round((last - first) / 1000 * 100) / 100;
                }
              }
              return null;
            })()}

            {/* ── Tab: Overview ── */}
            {activeTab === 'overview' && (<>

            {/* Pipeline-in-progress state (job without a report yet) */}
            {reportDetail.status === 'running' && !reportDetail.final_report && (
              <div className="rounded-xl border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-950/20 p-4 flex items-center gap-3">
                <span className="material-symbols-outlined text-amber-500 animate-spin">autorenew</span>
                <div className="min-w-0">
                  <p className="text-xs font-bold text-amber-600 dark:text-amber-400 uppercase tracking-wider">Pipeline in progress</p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    Current step: <Mono className="font-bold">{job?.currentStep ?? 'queued'}</Mono> — final report not generated yet.
                  </p>
                </div>
              </div>
            )}
            {reportDetail.status === 'failed' && (
              <div className="rounded-xl border border-red-200 dark:border-red-800/50 bg-red-50 dark:bg-red-950/20 p-4 flex items-center gap-3">
                <span className="material-symbols-outlined text-red-500">error</span>
                <div className="min-w-0">
                  <p className="text-xs font-bold text-red-600 dark:text-red-400 uppercase tracking-wider">Pipeline failed</p>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                    Step: <Mono className="font-bold">{job?.currentStep ?? 'unknown'}</Mono>
                    {job?.errorMessage && <> — {job.errorMessage}</>}
                  </p>
                </div>
              </div>
            )}

            {/* Risk gauge + status badges */}
            {(() => {
              const pct = Math.min(reportDetail.risk_score * 100, 100);
              const sev = normalizeSeverity(reportDetail.severity) ?? severityFromRisk(reportDetail.risk_score);
              const gaugeColor = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : pct >= 40 ? '#eab308' : '#10b981';
              const c = 2 * Math.PI * 40;
              return (
                <div className="flex items-center gap-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-700 p-4">
                  <div className="relative flex-shrink-0">
                    <svg width="72" height="72" viewBox="0 0 100 100" className="-rotate-90">
                      <circle cx="50" cy="50" r="40" fill="none" strokeWidth="10" className="stroke-slate-200 dark:stroke-slate-700" />
                      <circle cx="50" cy="50" r="40" fill="none" strokeWidth="10" stroke={gaugeColor} strokeLinecap="round"
                        strokeDasharray={`${(pct / 100) * c} ${c}`} className="transition-all duration-700" />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-sm font-black font-mono">{pct.toFixed(0)}%</span>
                    </div>
                  </div>
                  <div className="flex flex-col gap-2">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Final Risk Score</span>
                    <div className="flex gap-2 flex-wrap items-center">
                      <SeverityBadge severity={reportDetail.severity ?? sev} />
                      <StatusBadge status={reportDetail.status} />
                      <span className="px-2 py-0.5 rounded border border-slate-300 dark:border-slate-600 text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{reportDetail.event_type}</span>
                      {reportDetail.processing_time_seconds && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-blue-500/40 bg-blue-500/15 text-blue-500 dark:text-blue-400 text-[10px] font-bold uppercase tracking-wider">
                          <span className="material-symbols-outlined text-xs">timer</span>
                          {reportDetail.processing_time_seconds}s
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Processing Timeline */}
            {reportDetail.processing_time_seconds && (
              <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950/30 dark:to-indigo-950/30 rounded-xl p-4 border border-blue-200 dark:border-blue-800/50">
                <h4 className="text-xs font-bold uppercase tracking-wider text-blue-600 dark:text-blue-400 mb-3 flex items-center gap-1">
                  <span className="material-symbols-outlined text-sm">schedule</span>
                  Processing Timeline
                </h4>
                <div className="flex items-center gap-3">
                  <div className="flex flex-col items-center">
                    <span className="text-[9px] font-bold text-slate-400 uppercase">Input</span>
                    <span className="w-3 h-3 rounded-full bg-blue-500 mt-1"></span>
                  </div>
                  <div className="flex-1 relative">
                    <div className="h-1.5 bg-blue-200 dark:bg-blue-800 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-blue-500 to-indigo-500 rounded-full animate-pulse" style={{ width: '100%' }}></div>
                    </div>
                    <div className="absolute -top-5 left-1/2 -translate-x-1/2 text-xs font-black text-blue-600 dark:text-blue-400">
                      {reportDetail.processing_time_seconds}s total
                    </div>
                  </div>
                  <div className="flex flex-col items-center">
                    <span className="text-[9px] font-bold text-slate-400 uppercase">Report</span>
                    <span className="w-3 h-3 rounded-full bg-indigo-500 mt-1"></span>
                  </div>
                </div>
              </div>
            )}

            {/* Tier 1 Pre-Filter Result */}
            {reportDetail.tier1_filter && (
              <div className={`rounded-xl p-4 border ${reportDetail.tier1_filter.decision === 'SUSPICIOUS' ? 'bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/50' : 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/50'}`}>
                <h4 className="text-xs font-bold uppercase tracking-wider mb-3 flex items-center gap-1" style={{ color: reportDetail.tier1_filter.decision === 'SUSPICIOUS' ? '#d97706' : '#059669' }}>
                  <span className="material-symbols-outlined text-sm">filter_alt</span>
                  Tier 1 Pre-Filter Result
                </h4>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-lg text-xs font-bold uppercase ${reportDetail.tier1_filter.decision === 'SUSPICIOUS' ? 'bg-amber-200 dark:bg-amber-800/50 text-amber-700 dark:text-amber-300' : 'bg-emerald-200 dark:bg-emerald-800/50 text-emerald-700 dark:text-emerald-300'}`}>
                      <span className="material-symbols-outlined text-xs">{reportDetail.tier1_filter.decision === 'SUSPICIOUS' ? 'warning' : 'check_circle'}</span>
                      {reportDetail.tier1_filter.decision}
                    </span>
                    <span className="text-[10px] text-slate-500">→ {reportDetail.tier1_filter.decision === 'SUSPICIOUS' ? 'Escalated to Tier 2 LLM' : 'Passed — no escalation'}</span>
                  </div>
                </div>
                {/* Risk Score Bar */}
                <div className="mb-3">
                  <div className="flex justify-between text-[10px] font-bold text-slate-500 mb-1">
                    <span>Static Risk Score</span>
                    <span>{reportDetail.tier1_filter.static_risk_score}/100</span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-2 overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-700 ${reportDetail.tier1_filter.static_risk_score > 70 ? 'bg-red-500' : reportDetail.tier1_filter.static_risk_score > 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                      style={{ width: `${Math.min(reportDetail.tier1_filter.static_risk_score, 100)}%` }}></div>
                  </div>
                </div>
                {/* Matched Rules */}
                {reportDetail.tier1_filter.matched_rules?.length > 0 && (
                  <div className="mb-2">
                    <span className="text-[10px] font-bold text-slate-500 uppercase">Rules Matched ({reportDetail.tier1_filter.matched_rules.length}):</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {reportDetail.tier1_filter.matched_rules.map((rule: string) => (
                        <span key={rule} className="px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-[10px] font-mono font-bold text-slate-600 dark:text-slate-300">{rule}</span>
                      ))}
                    </div>
                  </div>
                )}
                {/* Model Info */}
                {reportDetail.tier1_filter.model && (
                  <div className="text-[10px] text-slate-400 mt-1">Model: {reportDetail.tier1_filter.model}</div>
                )}
              </div>
            )}

            {/* Final Report */}
            {reportDetail.final_report && (
              <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4 border border-slate-200 dark:border-slate-700">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-primary">description</span> Executive Summary</h4>
                <div className="prose prose-sm prose-slate dark:prose-invert max-w-none leading-relaxed">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>{reportDetail.final_report}</ReactMarkdown>
                </div>
              </div>
            )}

            </>)}

            {/* ── Tab: Evidence ── */}
            {activeTab === 'evidence' && (<>

            {/* Findings (evidence trail: claim + source) */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-amber-500">policy</span> Evidence Trail ({reportDetail.findings?.length || 0})</h4>
              <div className="space-y-2">
                {(reportDetail.findings || []).map((f: any, i: number) => (
                  <div key={i} className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-3">
                    <div className="flex justify-between items-start mb-1">
                      <Mono className="font-bold">{f.agent}</Mono>
                      <SeverityBadge severity={f.severity} />
                    </div>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">{f.description?.substring(0, 300)}</p>
                    {f.mitre_tactic && <p className="text-[10px] text-indigo-500 mt-1 font-bold">MITRE: {f.mitre_tactic}</p>}
                  </div>
                ))}
                {(reportDetail.findings || []).length === 0 && (
                  <p className="text-[11px] text-slate-500 italic">
                    {reportDetail.status === 'running' ? 'No evidence yet — the pipeline is still analyzing this artifact.' : 'No evidence recorded for this report.'}
                  </p>
                )}
              </div>
            </div>

            {/* MITRE techniques */}
            {reportDetail.mitre_techniques?.length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-indigo-500">grid_on</span> MITRE Techniques ({reportDetail.mitre_techniques.length})</h4>
                <div className="flex flex-wrap gap-1">
                  {reportDetail.mitre_techniques.map((t: string) => (
                    <Mono key={t} className="px-1.5 py-0.5 rounded border border-indigo-500/40 bg-indigo-500/15 text-indigo-500 dark:text-indigo-400 font-bold">{t}</Mono>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended actions */}
            {reportDetail.recommended_actions?.length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-emerald-500">task_alt</span> Recommended Actions ({reportDetail.recommended_actions.length})</h4>
                <ul className="space-y-1">
                  {reportDetail.recommended_actions.map((a: string, i: number) => (
                    <li key={i} className="flex items-start gap-2 text-[11px] text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2">
                      <span className="material-symbols-outlined text-sm text-emerald-500 mt-[-1px]">check_circle</span>
                      {a}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* IOCs */}
            {reportDetail.iocs?.length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-rose-500">bug_report</span> IOCs ({reportDetail.iocs.length})</h4>
                <div className="grid grid-cols-1 gap-1">
                  {reportDetail.iocs.map((ioc: any, i: number) => (
                    <div key={i} className="flex justify-between items-center bg-slate-50 dark:bg-slate-800 rounded px-3 py-2 text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${ioc.ioc_type === 'ip' ? 'bg-rose-100 text-rose-600' : 'bg-indigo-100 text-indigo-600'}`}>{ioc.ioc_type}</span>
                        <span className="font-mono font-bold">{ioc.value}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-400 text-[10px]">{ioc.source_agent}</span>
                        {ioc.ioc_type === 'ip' && (
                          blockedIPs.has(ioc.value) ? (
                            <span className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-red-100 dark:bg-red-900/30 text-red-600 text-[10px] font-bold">
                              <span className="material-symbols-outlined text-xs">block</span>BLOCKED
                            </span>
                          ) : (
                            <button
                              className="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-red-500 hover:bg-red-600 text-white text-[10px] font-bold transition-all hover:scale-105 active:scale-95 shadow-sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                setBlockedIPs(prev => new Set(prev).add(ioc.value));
                                setBlockToast(ioc.value);
                                setTimeout(() => setBlockToast(null), 3000);
                              }}
                            >
                              <span className="material-symbols-outlined text-xs">shield</span>Block IP
                            </button>
                          )
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            </>)}

            {/* Error Logs (Overview) */}
            {activeTab === 'overview' && reportDetail.error_logs?.length > 0 && (
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-red-500 mb-2">Errors ({reportDetail.error_logs.length})</h4>
                {reportDetail.error_logs.map((e: string, i: number) => (
                  <p key={i} className="text-[10px] text-red-400 font-mono bg-red-50 dark:bg-red-900/10 p-2 rounded mb-1">{e}</p>
                ))}
              </div>
            )}

            {/* ── Tab: Raw JSON ── */}
            {activeTab === 'json' && (
              <div className="rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden">
                <div className="px-3 py-2 bg-slate-100 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 flex items-center gap-2">
                  <span className="material-symbols-outlined text-sm text-slate-400">data_object</span>
                  <Mono className="font-bold text-slate-500">report.json</Mono>
                </div>
                <pre className="font-mono text-[11px] leading-relaxed bg-slate-950 text-slate-300 p-4 overflow-x-auto whitespace-pre">{JSON.stringify(reportDetail, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Block IP Toast */}
      {blockToast && (
        <div className="fixed bottom-6 right-6 z-50 animate-bounce">
          <div className="bg-red-600 text-white px-5 py-3 rounded-xl shadow-2xl flex items-center gap-3">
            <span className="material-symbols-outlined text-lg">block</span>
            <div>
              <div className="font-bold text-sm">IP Blocked Successfully</div>
              <div className="text-red-200 text-xs font-mono">{blockToast} → Firewall rule pushed</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
