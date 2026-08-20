import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Header } from '../components/Header';
import { SeverityBadge, StatusBadge, Mono, normalizeSeverity, severityFromRisk } from '../components/badges';
import { fetchStats, fetchReportDetail } from '../services/api';

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
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [reportDetail, setReportDetail] = useState<any>(null);
  const [blockedIPs, setBlockedIPs] = useState<Set<string>>(new Set());
  const [blockToast, setBlockToast] = useState<string | null>(null);
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

        {/* MITRE ATT&CK Donut Chart */}
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-8 shadow-sm mb-6 flex flex-col md:flex-row items-center md:items-start gap-8">
          <div className="flex-1 w-full">
            <h3 className="text-sm font-bold mb-8 flex items-center gap-2 text-slate-800 dark:text-slate-100 uppercase tracking-widest">
              MITRE ATT&CK
            </h3>
            
            {Object.keys(stats.mitre_tactics || {}).length === 0 ? (
              <div className="text-sm text-slate-500 w-full py-8 font-medium italic text-center">No MITRE tactics recorded yet.</div>
            ) : (
              <div className="flex flex-col md:flex-row items-center gap-12 md:gap-24 pl-4 md:pl-12">
                {/* Donut SVG */}
                <div className="relative flex-shrink-0">
                  <svg width="200" height="200" viewBox="0 0 100 100" className="-rotate-90">
                    {/* Inner light solid circle */}
                    <circle cx="50" cy="50" r="26" className="fill-blue-100 dark:fill-blue-900/40" />
                    
                    {/* Slices */}
                    {(() => {
                      const entries = Object.entries(stats.mitre_tactics || {}).sort((a: any, b: any) => b[1] - a[1]);
                      const totalMitre = entries.reduce((acc: any, [_, v]: any) => acc + (v as number), 0);
                      const mitreRadius = 40;
                      const mitreCircumference = 2 * Math.PI * mitreRadius;
                      let currentOffset = 0;
                      const colors = ['#2563eb', '#3b82f6', '#facc15', '#60a5fa', '#84cc16', '#a855f7', '#6366f1', '#ec4899'];

                      return entries.map(([tactic, count]: any, index) => {
                        const pct = count / totalMitre;
                        const dashLength = pct * mitreCircumference;
                        const offset = currentOffset;
                        currentOffset += dashLength;
                        const color = colors[index % colors.length];

                        return (
                          <circle 
                            key={tactic} 
                            cx="50" cy="50" r={mitreRadius} 
                            fill="none" 
                            stroke={color} 
                            strokeWidth="11"
                            strokeDasharray={`${dashLength} ${mitreCircumference - dashLength}`}
                            strokeDashoffset={-offset}
                            className="transition-all duration-1000 ease-out drop-shadow-sm"
                          />
                        );
                      });
                    })()}
                  </svg>
                </div>
                
                {/* Legend */}
                <div className="flex flex-col gap-3 justify-center">
                  {Object.entries(stats.mitre_tactics || {}).sort((a: any, b: any) => b[1] - a[1]).map(([tactic, count]: any, index) => {
                    const colors = ['#2563eb', '#3b82f6', '#facc15', '#60a5fa', '#84cc16', '#a855f7', '#6366f1', '#ec4899'];
                    const color = colors[index % colors.length];

                    return (
                      <div key={tactic} className="flex items-center gap-3">
                        <span className="w-3.5 h-3.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }}></span>
                        <div className="flex flex-col">
                          <span className="text-xs font-bold text-slate-800 dark:text-slate-200">{tactic}</span>
                        </div>
                        <span className="ml-auto text-[10px] font-bold bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full text-slate-500">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
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
            <h3 className="font-bold text-sm flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-base">history</span>
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
                  <tr key={r.report_id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer" onClick={async () => {
                    setSelectedReport(r);
                    setReportDetail(null);
                    setReportDetail(await fetchReportDetail(r.report_id));
                  }}>
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

        {/* Report Detail Drawer */}
        {selectedReport && (
          <div className="fixed inset-0 z-50 flex justify-end" onClick={() => { setSelectedReport(null); setReportDetail(null); }}>
            <div className="absolute inset-0 bg-black/40 backdrop-blur-sm"></div>
            <div className="relative w-full max-w-xl bg-white dark:bg-slate-900 shadow-2xl overflow-y-auto animate-slide-in" onClick={(e) => e.stopPropagation()}>
              <div className="sticky top-0 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 p-4 flex justify-between items-center z-10">
                <div>
                  <h3 className="font-black text-lg">Report Detail</h3>
                  <p className="font-mono text-xs text-primary">{selectedReport.report_id}</p>
                </div>
                <button onClick={() => { setSelectedReport(null); setReportDetail(null); }} className="size-8 rounded-lg bg-slate-100 dark:bg-slate-800 flex items-center justify-center hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors">
                  <span className="material-symbols-outlined text-sm">close</span>
                </button>
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

                  {/* Status Bar */}
                  <div className="flex gap-2 flex-wrap">
                    <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase ${reportDetail.status === 'completed' ? 'bg-green-100 dark:bg-green-900/30 text-green-600' : reportDetail.status === 'failed' ? 'bg-red-100 dark:bg-red-900/30 text-red-600' : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600'}`}>{reportDetail.status}</span>
                    <span className="px-3 py-1 rounded-lg text-xs font-bold bg-slate-100 dark:bg-slate-800 uppercase">{reportDetail.event_type}</span>
                    <span className={`px-3 py-1 rounded-lg text-xs font-bold ${(reportDetail.risk_score * 100) > 60 ? 'bg-red-100 dark:bg-red-900/30 text-red-600' : 'bg-amber-100 dark:bg-amber-900/30 text-amber-600'}`}>Risk: {(reportDetail.risk_score * 100).toFixed(0)}%</span>
                    {reportDetail.processing_time_seconds && (
                      <span className="px-3 py-1 rounded-lg text-xs font-bold bg-blue-100 dark:bg-blue-900/30 text-blue-600 flex items-center gap-1">
                        <span className="material-symbols-outlined text-xs">timer</span>
                        {reportDetail.processing_time_seconds}s
                      </span>
                    )}
                  </div>

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

                  {/* Findings */}
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-sm text-amber-500">policy</span> Findings ({reportDetail.findings?.length || 0})</h4>
                    <div className="space-y-2">
                      {(reportDetail.findings || []).map((f: any, i: number) => (
                        <div key={i} className="bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 p-3">
                          <div className="flex justify-between items-start mb-1">
                            <span className="text-xs font-bold text-slate-600 dark:text-slate-300">{f.agent}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                              f.severity === 'CRITICAL' ? 'bg-red-100 text-red-600' : f.severity === 'HIGH' ? 'bg-orange-100 text-orange-600' : f.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-600' : 'bg-slate-100 text-slate-600'
                            }`}>{f.severity}</span>
                          </div>
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">{f.description?.substring(0, 300)}</p>
                          {f.mitre_tactic && <p className="text-[10px] text-indigo-500 mt-1 font-bold">MITRE: {f.mitre_tactic}</p>}
                        </div>
                      ))}
                    </div>
                  </div>

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

                  {/* Error Logs */}
                  {reportDetail.error_logs?.length > 0 && (
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-red-500 mb-2">Errors ({reportDetail.error_logs.length})</h4>
                      {reportDetail.error_logs.map((e: string, i: number) => (
                        <p key={i} className="text-[10px] text-red-400 font-mono bg-red-50 dark:bg-red-900/10 p-2 rounded mb-1">{e}</p>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

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
}
