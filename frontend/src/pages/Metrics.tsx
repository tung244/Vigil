import { useEffect, useState } from 'react';
import { Header } from '../components/Header';
import { SeverityBadge, StatusBadge, Mono, normalizeSeverity, severityFromRisk } from '../components/badges';
import { ReportFlyout } from '../components/ReportFlyout';
import { fetchStats, fetchMitreStats } from '../services/api';
import type { MitreStats } from '../services/api';
import { MitreHeatmap } from '../components/MitreHeatmap';

type Verdict = 'MALICIOUS' | 'SUSPICIOUS' | 'SAFE';

const verdictOf = (r: any): Verdict => {
  const score = r.risk_score * 100;
  const hasCritical = r.findings?.some?.((f: any) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  let verdict: Verdict = score > 70 ? 'MALICIOUS' : score > 40 ? 'SUSPICIOUS' : 'SAFE';
  if (verdict === 'SAFE' && hasCritical) verdict = 'SUSPICIOUS';
  return verdict;
};

const VERDICT_CLASSES: Record<Verdict, string> = {
  MALICIOUS: 'bg-red-500/15 text-red-400 border-red-500/40',
  SUSPICIOUS: 'bg-amber-500/15 text-amber-400 border-amber-500/40',
  SAFE: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
};
const VERDICT_ICONS: Record<Verdict, string> = {
  MALICIOUS: 'gpp_bad',
  SUSPICIOUS: 'warning',
  SAFE: 'verified_user',
};

export default function Metrics() {
  const [stats, setStats] = useState<any>(null);
  const [mitre, setMitre] = useState<MitreStats | null>(null);
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [sortKey, setSortKey] = useState<'time' | 'risk'>('time');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [sevFilter, setSevFilter] = useState('all');
  const [verdictFilter, setVerdictFilter] = useState('all');

  const toggleSort = (key: 'time' | 'risk') => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
    setPage(1);
  };

  useEffect(() => {
    const load = async () => {
      setStats(await fetchStats());
      setMitre(await fetchMitreStats());
    };
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!stats) {
    return (
      <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen font-display">
        <Header />
        <div className="flex items-center justify-center h-[80vh]">
          <div className="flex flex-col items-center gap-4">
            <span className="material-symbols-outlined text-primary text-5xl animate-spin">autorenew</span>
            <p className="text-slate-500 font-bold text-sm">Loading metrics data...</p>
            <p className="text-slate-400 text-xs">Trigger some analyses first to populate the dashboard</p>
          </div>
        </div>
      </div>
    );
  }

  const { severity_breakdown: sev, agent_usage: agents, event_type_breakdown: events, risk_histogram: hist } = stats;
  const maxSev = Math.max(sev.critical, sev.high, sev.medium, sev.low, 1);
  const totalAgents = Math.max(agents.email_analyst + agents.forensic_analyst + agents.threat_intel, 1);
  const totalEvents = Math.max(events.email + events.cloudtrail, 1);
  const maxHist = Math.max(...hist, 1);

  // Donut chart calculations
  const agentData = [
    { label: 'Email', value: agents.email_analyst, color: '#ec5b13' },
    { label: 'Tier-1 Filter', value: agents.forensic_analyst, color: '#10b981' },
    { label: 'Threat Intel', value: agents.threat_intel, color: '#6366f1' },
  ];
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  let cumulativeOffset = 0;

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen font-display">
      <Header />

      <main className="max-w-[1440px] mx-auto p-6 space-y-6">
        {/* Title */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-black tracking-tight">SOC Metrics & Analytics</h1>
            <p className="text-slate-500 text-sm mt-1">Aggregated intelligence from all completed investigations</p>
          </div>
          <div className="flex items-center gap-2 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 px-3 py-1.5 rounded-lg text-xs font-bold">
            <span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-500 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span></span>
            Live — Auto-refresh 5s
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {[
            { label: 'Total Reports', value: stats.total_reports, icon: 'assignment', color: 'text-primary' },
            { label: 'Completed', value: stats.completed_reports, icon: 'check_circle', color: 'text-emerald-500' },
            { label: 'Failed', value: stats.failed_reports, icon: 'error', color: 'text-red-500' },
            { label: 'Total Findings', value: stats.total_findings, icon: 'policy', color: 'text-amber-500' },
            { label: 'IOCs Collected', value: stats.total_iocs, icon: 'bug_report', color: 'text-rose-500' },
            { label: 'Avg Risk', value: `${(stats.avg_risk_score * 100).toFixed(1)}%`, icon: 'speed', color: 'text-violet-500' },
          ].map((kpi) => (
            <div key={kpi.label} className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4 flex flex-col gap-2 hover:-translate-y-1 transition-transform shadow-sm">
              <div className="flex justify-between items-start">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{kpi.label}</span>
                <span className={`material-symbols-outlined ${kpi.color} text-lg`}>{kpi.icon}</span>
              </div>
              <span className="text-2xl font-black">{kpi.value}</span>
            </div>
          ))}
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Severity Distribution */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
            <h3 className="text-sm font-bold mb-5 flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-base">bar_chart</span>
              Severity Distribution
            </h3>
            <div className="space-y-4">
              {[
                { label: 'Critical', value: sev.critical, color: 'bg-red-500' },
                { label: 'High', value: sev.high, color: 'bg-orange-500' },
                { label: 'Medium', value: sev.medium, color: 'bg-amber-400' },
                { label: 'Low', value: sev.low, color: 'bg-emerald-500' },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-3">
                  <span className="text-xs font-bold w-16 text-slate-600 dark:text-slate-400">{item.label}</span>
                  <div className="flex-1 bg-slate-100 dark:bg-slate-800 rounded-full h-3 overflow-hidden">
                    <div className={`h-full ${item.color} rounded-full transition-all duration-700`} style={{ width: `${(item.value / maxSev) * 100}%` }}></div>
                  </div>
                  <span className="text-xs font-black w-8 text-right">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Agent Workload Donut */}
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm flex flex-col items-center">
            <h3 className="text-sm font-bold mb-5 flex items-center gap-2 self-start">
              <span className="material-symbols-outlined text-primary text-base">donut_large</span>
              Agent Workload
            </h3>
            <div className="relative">
              <svg width="160" height="160" viewBox="0 0 100 100" className="-rotate-90">
                {agentData.map((agent) => {
                  const pct = agent.value / totalAgents;
                  const dashLength = pct * circumference;
                  const offset = cumulativeOffset;
                  cumulativeOffset += dashLength;
                  return (
                    <circle key={agent.label} cx="50" cy="50" r={radius} fill="none" stroke={agent.color} strokeWidth="12"
                      strokeDasharray={`${dashLength} ${circumference - dashLength}`}
                      strokeDashoffset={-offset}
                      className="transition-all duration-700"
                    />
                  );
                })}
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-black">{totalAgents}</span>
                <span className="text-[10px] text-slate-500 font-bold">TASKS</span>
              </div>
            </div>
            <div className="flex gap-4 mt-4">
              {agentData.map((a) => (
                <div key={a.label} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: a.color }}></span>
                  <span className="text-[10px] font-bold text-slate-500">{a.label} ({a.value})</span>
                </div>
              ))}
            </div>
          </div>

          {/* Event Type + Risk Histogram */}
          <div className="space-y-6">
            {/* Event Type Split */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-base">category</span>
                Event Type Split
              </h3>
              <div className="flex h-6 rounded-full overflow-hidden bg-slate-100 dark:bg-slate-800">
                <div className="bg-primary h-full transition-all duration-700 flex items-center justify-center" style={{ width: `${(events.email / totalEvents) * 100}%` }}>
                  {events.email > 0 && <span className="text-[9px] font-bold text-white px-1">Email {events.email}</span>}
                </div>
                <div className="bg-indigo-500 h-full transition-all duration-700 flex items-center justify-center" style={{ width: `${(events.cloudtrail / totalEvents) * 100}%` }}>
                  {events.cloudtrail > 0 && <span className="text-[9px] font-bold text-white px-1">Log files {events.cloudtrail}</span>}
                </div>
              </div>
              <div className="flex justify-between mt-2">
                <span className="text-[10px] text-slate-500 flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-primary"></span> Email</span>
                <span className="text-[10px] text-slate-500 flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-500"></span> Log Files</span>
              </div>
            </div>

            {/* Risk Score Histogram */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
              <h3 className="text-sm font-bold mb-4 flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-base">equalizer</span>
                Risk Score Distribution
              </h3>
              <div className="flex items-end gap-2 h-24">
                {['0-20', '20-40', '40-60', '60-80', '80-100'].map((label, i) => (
                  <div key={label} className="flex-1 flex flex-col items-center gap-1">
                    <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-t relative overflow-hidden" style={{ height: '80px' }}>
                      <div
                        className={`absolute bottom-0 w-full rounded-t transition-all duration-700 ${i >= 3 ? 'bg-red-500' : i >= 2 ? 'bg-amber-400' : 'bg-emerald-500'}`}
                        style={{ height: `${(hist[i] / maxHist) * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-[8px] font-bold text-slate-400">{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Heatmap */}
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm mb-6">
          <h3 className="text-sm font-bold mb-5 flex items-center gap-2 text-slate-800 dark:text-slate-100 uppercase tracking-widest">
            <span className="material-symbols-outlined text-primary text-base">grid_on</span>
            MITRE ATT&CK Coverage
          </h3>
          <MitreHeatmap data={mitre} />
        </div>


        {/* Alerts Table — dense SOC style */}
        {(() => {
          const allReports: any[] = stats.recent_reports || [];
          const rowSeverity = (r: any) => r.severity ?? severityFromRisk(r.risk_score);
          const filtered = allReports
            .filter((r) => sevFilter === 'all' || normalizeSeverity(rowSeverity(r)) === sevFilter)
            .filter((r) => verdictFilter === 'all' || verdictOf(r) === verdictFilter)
            .sort((a, b) => {
              const av = sortKey === 'risk' ? a.risk_score : new Date(a.created_at ?? 0).getTime();
              const bv = sortKey === 'risk' ? b.risk_score : new Date(b.created_at ?? 0).getTime();
              return sortDir === 'asc' ? (av > bv ? 1 : av < bv ? -1 : 0) : (av < bv ? 1 : av > bv ? -1 : 0);
            });
          const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
          const safePage = Math.min(page, totalPages);
          const paged = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);
          const sortIcon = (key: 'time' | 'risk') =>
            sortKey !== key ? 'unfold_more' : sortDir === 'asc' ? 'arrow_upward' : 'arrow_downward';
          const thBtn = 'inline-flex items-center gap-1 hover:text-slate-700 dark:hover:text-slate-200 transition-colors cursor-pointer select-none';

          return (
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
          <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 flex flex-wrap justify-between items-center gap-2">
            <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              <span className="material-symbols-outlined text-primary text-sm">history</span>
              Alerts — Recent Investigations
            </h3>
            <div className="flex items-center gap-2">
              <select
                value={sevFilter}
                onChange={(e) => { setSevFilter(e.target.value); setPage(1); }}
                className="text-[10px] font-bold bg-slate-100 dark:bg-slate-800 border-0 rounded-lg px-2 py-1 text-slate-600 dark:text-slate-300 cursor-pointer uppercase"
              >
                <option value="all">Severity: All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={verdictFilter}
                onChange={(e) => { setVerdictFilter(e.target.value); setPage(1); }}
                className="text-[10px] font-bold bg-slate-100 dark:bg-slate-800 border-0 rounded-lg px-2 py-1 text-slate-600 dark:text-slate-300 cursor-pointer uppercase"
              >
                <option value="all">Verdict: All</option>
                <option value="MALICIOUS">Malicious</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="SAFE">Safe</option>
              </select>
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">{filtered.length} / {allReports.length}</span>
              <select
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
                className="text-[10px] font-bold bg-slate-100 dark:bg-slate-800 border-0 rounded-lg px-2 py-1 text-slate-600 dark:text-slate-300 cursor-pointer"
              >
                <option value={10}>10 / page</option>
                <option value={20}>20 / page</option>
                <option value={50}>50 / page</option>
              </select>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 dark:border-slate-800 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                  <th className="px-2 py-1.5 pl-3">Report ID</th>
                  <th className="px-2 py-1.5">Type</th>
                  <th className="px-2 py-1.5">Severity</th>
                  <th className="px-2 py-1.5">Verdict</th>
                  <th className="px-2 py-1.5">Status</th>
                  <th className="px-2 py-1.5">
                    <button className={thBtn} onClick={() => toggleSort('risk')}>
                      Risk Score <span className="material-symbols-outlined text-xs">{sortIcon('risk')}</span>
                    </button>
                  </th>
                  <th className="px-2 py-1.5">Findings</th>
                  <th className="px-2 py-1.5">
                    <button className={thBtn} onClick={() => toggleSort('time')}>
                      Time <span className="material-symbols-outlined text-xs">{sortIcon('time')}</span>
                    </button>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {paged.length > 0 ? paged.map((r: any) => {
                  const verdict = verdictOf(r);
                  return (
                  <tr key={r.report_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer" onClick={() => setSelectedReport(r)}>
                    <td className="px-2 py-1.5 pl-3"><Mono className="font-bold text-primary">{r.report_id}</Mono></td>
                    <td className="px-2 py-1.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${r.event_type === 'email' ? 'bg-primary/10 text-primary' : 'bg-indigo-500/15 text-indigo-500 dark:text-indigo-400'}`}>
                        {r.event_type}
                      </span>
                    </td>
                    <td className="px-2 py-1.5"><SeverityBadge severity={rowSeverity(r)} /></td>
                    <td className="px-2 py-1.5">
                      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase ${VERDICT_CLASSES[verdict]}`}>
                        <span className="material-symbols-outlined text-xs">{VERDICT_ICONS[verdict]}</span>
                        {verdict}
                      </span>
                    </td>
                    <td className="px-2 py-1.5"><StatusBadge status={r.status} /></td>
                    <td className="px-2 py-1.5">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div className={`h-full rounded-full transition-all ${(r.risk_score * 100) > 70 ? 'bg-red-500' : (r.risk_score * 100) > 40 ? 'bg-amber-400' : 'bg-emerald-500'}`} style={{ width: `${Math.min(r.risk_score * 100, 100)}%` }}></div>
                        </div>
                        <span className="text-[11px] font-bold font-mono">{(r.risk_score * 100).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-[11px] font-bold font-mono">{r.finding_count}</span>
                    </td>
                    <td className="px-2 py-1.5">
                      <Mono className="text-slate-400">{r.created_at ? new Date(r.created_at).toLocaleString('en-GB', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '—'}</Mono>
                    </td>
                  </tr>
                  );
                }) : (
                  <tr><td colSpan={8} className="p-6 text-center text-slate-500 text-sm">No investigations match the current filters.</td></tr>
                )}
              </tbody>
            </table>
          </div>
          {/* Pagination Controls */}
          {filtered.length > 0 && (
            <div className="px-3 py-2 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 flex justify-between items-center">
              <span className="text-[10px] font-bold text-slate-400">
                Showing {Math.min((safePage - 1) * pageSize + 1, filtered.length)}–{Math.min(safePage * pageSize, filtered.length)} of {filtered.length}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={safePage <= 1}
                  className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                >
                  <span className="material-symbols-outlined text-xs">chevron_left</span> Prev
                </button>
                <span className="px-3 py-1 text-[10px] font-black text-primary">
                  {safePage} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={safePage >= totalPages}
                  className="px-2.5 py-1 rounded-lg text-[10px] font-bold bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 disabled:opacity-30 disabled:cursor-not-allowed transition-colors flex items-center gap-1"
                >
                  Next <span className="material-symbols-outlined text-xs">chevron_right</span>
                </button>
              </div>
            </div>
          )}
        </div>
          );
        })()}

        {/* Report Detail Flyout (shared component, W8) */}
        {selectedReport && (
          <ReportFlyout reportId={selectedReport.report_id} onClose={() => setSelectedReport(null)} />
        )}
      </main>
    </div>
  );
}
