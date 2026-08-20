import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Link } from 'react-router-dom';
import { Header } from '../components/Header';
import { fetchLatestReport, fetchNodes, fetchTraces, uploadFile } from '../services/api';
import type { Report, GraphNodeStatus, TraceEvent } from '../types';

// Pipeline node definitions
const PIPELINE_NODES = [
  { id: 'eventbridge', label: 'Upload API', icon: 'sensors', matchSources: ['Upload API'] },
  { id: 'supervisor', label: 'Supervisor', icon: 'hub', matchSources: ['Supervisor'] },
  { id: 'agents', label: 'Analysis Agents', icon: 'groups', matchSources: ['Email Analyst', 'Forensic Analyst', 'Threat Intel'] },
  { id: 'synthesis', label: 'Synthesis', icon: 'summarize', matchSources: ['Synthesis'] },
  { id: 'verdict', label: 'Final Verdict', icon: 'verified_user', matchSources: [] },
];

function getPipelineStatus(nodes: GraphNodeStatus[], report: Report | null, traces: TraceEvent[]) {
  const lastTraceSource = traces.length > 0 ? traces[traces.length - 1].source : '';
  const isCompleted = report?.status === 'completed';
  const isFailed = report?.status === 'failed';
  const isRunning = report?.status === 'running';
  const hasFinalReport = !!report?.final_report;

  return PIPELINE_NODES.map((pn) => {
    let status: 'idle' | 'running' | 'completed' | 'error' = 'idle';

    if (pn.id === 'eventbridge') {
      if (report) status = 'completed';
    } else if (pn.id === 'supervisor') {
      if (isCompleted || hasFinalReport) status = 'completed';
      else if (isRunning && (lastTraceSource === 'Supervisor' || pn.matchSources.includes(lastTraceSource))) status = 'running';
      else if (report && traces.length > 1) status = 'completed';
    } else if (pn.id === 'agents') {
      const agentNodes = nodes.filter(n => n.type !== 'supervisor');
      const anyRunning = agentNodes.some(n => n.status === 'running');
      const anyCompleted = agentNodes.some(n => n.status === 'completed');
      if (isCompleted || hasFinalReport) status = 'completed';
      else if (anyRunning) status = 'running';
      else if (anyCompleted) status = 'completed';
    } else if (pn.id === 'synthesis') {
      if (hasFinalReport) status = 'completed';
      else if (isRunning && lastTraceSource === 'Synthesis') status = 'running';
    } else if (pn.id === 'verdict') {
      if (hasFinalReport) status = 'completed';
      if (isFailed) status = 'error';
    }
    return { ...pn, status };
  });
}

export default function SOCDashboard() {
  const [report, setReport] = useState<Report | null>(null);
  const [nodes, setNodes] = useState<GraphNodeStatus[]>([]);
  const [traces, setTraces] = useState<TraceEvent[]>([]);
  const [auditTrail, setAuditTrail] = useState<{ time: string, action: string, user: string }[]>([]);
  const [showExplain, setShowExplain] = useState(false);
  const [showIntel, setShowIntel] = useState(false);
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [showFPFeedback, setShowFPFeedback] = useState(false);
  const [incidentStatus, setIncidentStatus] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [expandedTraceId, setExpandedTraceId] = useState<string | null>(null);
  const [expandedPipelineNode, setExpandedPipelineNode] = useState<string | null>(null);
  const [soarActions, setSoarActions] = useState<{ label: string, status: string, icon: string }[] | null>(null);

  const handleHiTLAction = async (action: string) => {
    // Note: the old RLHF feedback endpoint has no Vigil equivalent — HiTL
    // actions only update local UI state (audit trail / SOAR simulation).
    if (action === 'Marked False Positive') {
      setShowFPFeedback(true);
    }
    if (action === 'Escalated to Tier 3') {
      setIncidentStatus('HUMAN_INVESTIGATION');
    }
    if (action === 'Approved Mitigation') {
      // Trigger SOAR simulation
      const actions = [
        { label: report?.iocs?.length ? `Blocking ${report.iocs.length} IOCs on Firewall` : 'Blocking IOCs on Firewall', status: 'pending', icon: 'shield' },
        { label: report?.event_type === 'email' ? 'Purging malicious email from mailboxes' : 'Isolating affected hosts via EDR', status: 'pending', icon: report?.event_type === 'email' ? 'delete_sweep' : 'desktop_access_disabled' },
        { label: `Creating JIRA ticket for ${report?.report_id || 'incident'}`, status: 'pending', icon: 'confirmation_number' },
        { label: 'Updating threat intelligence feeds', status: 'pending', icon: 'update' },
      ];
      setSoarActions(actions);
      // Simulate sequential completion
      actions.forEach((_, i) => {
        setTimeout(() => {
          setSoarActions(prev => prev ? prev.map((a, j) => j <= i ? { ...a, status: 'done' } : j === i + 1 ? { ...a, status: 'running' } : a) : null);
        }, (i + 1) * 1200);
      });
      setTimeout(() => {
        setIncidentStatus('RESOLVED');
      }, actions.length * 1200 + 500);
    }
    setAuditTrail(prev => [{
      time: new Date().toLocaleTimeString(),
      action,
      user: "SOC_Analyst_01"
    }, ...prev]);
  };

  useEffect(() => {
    const loadData = async () => {
      setReport(await fetchLatestReport());
      setNodes(await fetchNodes());
      setTraces(await fetchTraces());
    };
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const riskScore = report?.risk_score ? (report.risk_score * 100).toFixed(0) : '0';
  const activeAlerts = report?.findings?.length || 0;
  const isRunning = nodes.some(n => n.status === 'running');
  const agentHealth = (() => {
    if (report?.status === 'failed') return 'Error';
    if (!report || report.status === 'completed') return '100%';
    // Calculate from actual node status
    const agentNodes = nodes.filter(n => n.type !== 'supervisor');
    if (agentNodes.length === 0) return '100%';
    const responded = agentNodes.filter(n => n.status === 'completed' || n.status === 'running').length;
    return `${Math.round((responded / agentNodes.length) * 100)}%`;
  })();
  const pipelineNodes = getPipelineStatus(nodes, report, traces);

  // Get detail data for a specific trace step
  const getTraceDetails = (trace: TraceEvent) => {
    if (!report) return null;
    const source = trace.source;
    const agentFindings = (report.findings || []).filter((f: any) => {
      const agentName = (f.agent || '').toLowerCase();
      return source.toLowerCase().includes('email') ? agentName.includes('email') :
        source.toLowerCase().includes('forensic') ? agentName.includes('forensic') :
          source.toLowerCase().includes('threat') ? agentName.includes('threat') :
            false;
    });
    const agentIOCs = (report.iocs || []).filter((ioc: any) => {
      const srcAgent = (ioc.source_agent || '').toLowerCase();
      return source.toLowerCase().includes('email') ? srcAgent.includes('email') :
        source.toLowerCase().includes('forensic') ? srcAgent.includes('forensic') :
          source.toLowerCase().includes('threat') ? srcAgent.includes('threat') :
            false;
    });

    // For Synthesis, include the final report content
    const isSynthesis = source.toLowerCase().includes('synthes');
    return {
      findings: agentFindings,
      iocs: agentIOCs,
      final_report: isSynthesis ? report.final_report : undefined,
      risk_score: isSynthesis ? report.risk_score : undefined
    };
  };

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen font-display">
      <Header />

      <main className="max-w-[1440px] mx-auto p-6 space-y-6">
        {/* ═══ INLINE PIPELINE VISUALIZATION ═══ */}
        <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 shadow-sm">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-sm font-bold flex items-center gap-2">
              <span className="material-symbols-outlined text-primary text-base">account_tree</span>
              Live Agent Pipeline
            </h3>
            <div className="flex items-center gap-2">
              {report?.status === 'running' && (
                <span className="flex items-center gap-1.5 text-[10px] font-bold text-amber-600 bg-amber-100 dark:bg-amber-900/30 px-2 py-1 rounded-lg animate-pulse">
                  <span className="relative flex h-2 w-2"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-500 opacity-75"></span><span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span></span>
                  PROCESSING
                </span>
              )}
              {incidentStatus === 'RESOLVED' && (
                <span className="flex items-center gap-1.5 text-[10px] font-bold text-emerald-600 bg-emerald-100 dark:bg-emerald-900/30 px-2 py-1 rounded-lg">
                  <span className="material-symbols-outlined text-xs">check_circle</span> RESOLVED
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between gap-0 overflow-x-auto py-2">
            {pipelineNodes.map((node, i) => {
              // Map node id to the backend pipeline_logs node names
              const nodeLogMap: Record<string, string[]> = {
                'eventbridge': ['eventbridge'],
                'supervisor': ['supervisor'],
                'agents': ['email_analyst', 'forensic_analyst', 'threat_intel'],
                'synthesis': ['synthesis'],
                'verdict': ['verdict'],
              };
              const matchNodes = nodeLogMap[node.id] || [];
              const nodeLogs = ((report as any)?.pipeline_logs || []).filter((l: any) => matchNodes.includes(l.node));
              const hasLogs = nodeLogs.length > 0;

              return (
                <div key={node.id} className="flex items-center flex-1 min-w-0">
                  {/* Node */}
                  <div
                    className="flex flex-col items-center gap-2 flex-shrink-0 group relative cursor-pointer"
                    onClick={() => hasLogs ? setExpandedPipelineNode(expandedPipelineNode === node.id ? null : node.id) : null}
                  >
                    <div className={`size-12 rounded-xl flex items-center justify-center transition-all duration-500 relative
                      ${node.status === 'completed' ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-600 border-2 border-emerald-300 dark:border-emerald-700 shadow-sm shadow-emerald-200' :
                        node.status === 'running' ? 'bg-primary/10 text-primary border-2 border-primary shadow-lg shadow-primary/20' :
                          node.status === 'error' ? 'bg-red-100 dark:bg-red-900/40 text-red-600 border-2 border-red-300 dark:border-red-700' :
                            'bg-slate-100 dark:bg-slate-800 text-slate-400 border-2 border-slate-200 dark:border-slate-700'}
                    `}>
                      {node.status === 'running' && (
                        <span className="absolute inset-0 rounded-xl border-2 border-primary animate-ping opacity-30"></span>
                      )}
                      {node.status === 'completed' ? (
                        <span className="material-symbols-outlined text-lg">check_circle</span>
                      ) : (
                        <span className="material-symbols-outlined text-lg">{node.icon}</span>
                      )}
                    </div>
                    <span className={`text-[10px] font-bold text-center w-20 leading-tight
                      ${node.status === 'running' ? 'text-primary' : node.status === 'completed' ? 'text-emerald-600' : 'text-slate-400'}
                    `}>{node.label}</span>
                    {/* Activity count badge */}
                    {hasLogs && (
                      <span className={`absolute -top-1 -right-1 size-4 rounded-full text-white flex items-center justify-center text-[8px]
                        ${node.status === 'completed' ? 'bg-emerald-500' : node.status === 'running' ? 'bg-primary animate-bounce' : node.status === 'error' ? 'bg-red-500' : 'bg-slate-400'}
                      `}>
                        {nodeLogs.length}
                      </span>
                    )}
                    {node.status !== 'idle' && !hasLogs && (
                      <span className={`absolute -top-1 -right-1 size-4 rounded-full text-white flex items-center justify-center text-[8px]
                        ${node.status === 'completed' ? 'bg-emerald-500' : node.status === 'running' ? 'bg-primary animate-bounce' : 'bg-red-500'}
                      `}>
                        {node.status === 'completed' ? '✓' : node.status === 'running' ? '⟳' : '!'}
                      </span>
                    )}
                  </div>

                  {/* Arrow connector */}
                  {i < pipelineNodes.length - 1 && (
                    <div className="flex-1 mx-1 h-0.5 relative min-w-[20px]">
                      <div className={`absolute inset-0 rounded-full transition-all duration-700
                        ${node.status === 'completed' ? 'bg-gradient-to-r from-emerald-400 to-emerald-300' :
                          node.status === 'running' ? 'bg-gradient-to-r from-primary/60 to-primary/20' :
                            'bg-slate-200 dark:bg-slate-700'}
                      `}></div>
                      {node.status === 'running' && (
                        <div className="absolute top-1/2 -translate-y-1/2 size-2 rounded-full bg-primary animate-[moveRight_1.5s_ease-in-out_infinite]"></div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* ═══ EXPANDED PIPELINE NODE ACTIVITY LOG ═══ */}
          {expandedPipelineNode && (() => {
            const nodeLogMap: Record<string, string[]> = {
              'eventbridge': ['eventbridge'],
              'supervisor': ['supervisor'],
              'agents': ['email_analyst', 'forensic_analyst', 'threat_intel'],
              'synthesis': ['synthesis'],
              'verdict': ['verdict'],
            };
            const matchNodes = nodeLogMap[expandedPipelineNode] || [];
            const nodeLogs = ((report as any)?.pipeline_logs || []).filter((l: any) => matchNodes.includes(l.node));
            const nodeLabel = PIPELINE_NODES.find(n => n.id === expandedPipelineNode)?.label || expandedPipelineNode;

            return nodeLogs.length > 0 ? (
              <div className="mt-3 bg-slate-900 rounded-lg border border-slate-700 overflow-hidden animate-fade-in">
                <div className="p-2.5 border-b border-slate-800 flex items-center justify-between">
                  <div className="flex items-center gap-2 text-emerald-400">
                    <span className="material-symbols-outlined text-sm">terminal</span>
                    <span className="text-[10px] font-bold uppercase tracking-widest">Activity Log — {nodeLabel}</span>
                    <span className="text-[10px] text-slate-500 font-normal">({nodeLogs.length} entries)</span>
                  </div>
                  <button onClick={() => setExpandedPipelineNode(null)} className="text-slate-500 hover:text-white transition-colors">
                    <span className="material-symbols-outlined text-sm">close</span>
                  </button>
                </div>
                <div className="p-2 max-h-48 overflow-y-auto space-y-1">
                  {nodeLogs.map((log: any, li: number) => (
                    <div key={li} className="flex items-start gap-2.5 p-2 rounded-lg bg-slate-800/50 hover:bg-slate-800 transition-colors group">
                      <div className="size-5 rounded flex items-center justify-center bg-emerald-900/30 text-emerald-400 mt-0.5 flex-shrink-0">
                        <span className="material-symbols-outlined text-[11px]">
                          {log.action?.toLowerCase().includes('routing') ? 'fork_right' :
                            log.action?.toLowerCase().includes('evaluat') ? 'psychology' :
                              log.action?.toLowerCase().includes('generat') ? 'draw' :
                                log.action?.toLowerCase().includes('risk') ? 'speed' :
                                  log.action?.toLowerCase().includes('event') || log.action?.toLowerCase().includes('file') ? 'sensors' :
                                    log.action?.toLowerCase().includes('complete') ? 'check_circle' :
                                      'arrow_forward'}
                        </span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-[11px] font-bold text-slate-200">{log.action}</span>
                          <span className="text-[9px] text-slate-500 flex-shrink-0">{log.ts ? new Date(log.ts).toLocaleTimeString() : ''}</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed mt-0.5">{log.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null;
          })()}
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">AI Confidence Score</span>
              <span className="material-symbols-outlined text-primary">psychology_alt</span>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-bold">{riskScore}</span>
              <span className="text-slate-400 text-sm font-medium">%</span>
            </div>
            <div className="w-full bg-slate-100 dark:bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${Number(riskScore) > 80 ? 'bg-gradient-to-r from-red-500 to-red-600' : Number(riskScore) > 50 ? 'bg-gradient-to-r from-orange-400 to-orange-500' : 'bg-gradient-to-r from-emerald-400 to-emerald-500'}`}
                style={{ width: `${riskScore}%` }}></div>
            </div>
            <p className="text-emerald-500 text-xs font-medium mt-1">Based on multi-agent consensus</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Active Alerts</span>
              <span className="material-symbols-outlined text-red-500">warning</span>
            </div>
            <span className="text-3xl font-bold">{activeAlerts} High</span>
            <p className="text-slate-400 text-xs mt-1">Detected in current analysis trace</p>
            <p className="text-orange-500 text-xs font-medium mt-auto">Awaiting Mitigation</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Agent Health</span>
              <span className="material-symbols-outlined text-emerald-500">memory</span>
            </div>
            <span className="text-3xl font-bold">{agentHealth}</span>
            <p className="text-slate-400 text-xs mt-1">{nodes.filter(n => n.status !== 'error').length} agents responding</p>
            <p className="text-emerald-500 text-xs font-medium mt-auto">{isRunning ? 'Actively investigating...' : 'System Idle'}</p>
          </div>
          <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col gap-2 hover:-translate-y-1 transition-transform cursor-default shadow-sm">
            <div className="flex justify-between items-start">
              <span className="text-slate-500 dark:text-slate-400 text-xs font-bold uppercase tracking-wider">Impact Analysis</span>
              <span className="material-symbols-outlined text-rose-500">groups</span>
            </div>
            <span className="text-3xl font-bold">{report?.iocs?.length ? Math.max(1, Math.floor(report.iocs.length / 2)) : 0}</span>
            <p className="text-slate-400 text-xs mt-1">Users/Systems Affected</p>
            <p className="text-rose-500 text-xs font-medium mt-auto">Requires Immediate Review</p>
          </div>
        </div>

        {/* Main Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Active Investigation Section */}
          <div className="lg:col-span-8 space-y-6">
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-slate-50 dark:bg-slate-900/50">
                <div className="flex items-center gap-3">
                  <span className="p-1.5 bg-red-100 dark:bg-red-900/30 text-red-600 rounded">
                    <span className="material-symbols-outlined text-lg">bolt</span>
                  </span>
                  <div>
                    <h3 className="font-bold text-sm flex items-center gap-2">
                      {report?.report_id ? `Incident: ${report.report_id}` : 'Waiting for incoming events...'}
                      {incidentStatus === 'HUMAN_INVESTIGATION' && (
                        <span className="bg-rose-600 text-[10px] text-white px-2 py-0.5 rounded-full animate-pulse border border-rose-400 shadow-sm shadow-rose-900/40">
                          HUMAN INVESTIGATION IN PROGRESS
                        </span>
                      )}
                      {incidentStatus === 'RESOLVED' && (
                        <span className="bg-emerald-600 text-[10px] text-white px-2 py-0.5 rounded-full border border-emerald-400">
                          RESOLVED
                        </span>
                      )}
                    </h3>
                    <p className="text-xs text-slate-500">
                      {report?.event_type ? `Type: ${report.event_type.toUpperCase()}` : 'No active incident'}
                    </p>
                  </div>
                </div>
                <div className="flex gap-2 w-full sm:w-auto items-center">
                  <span className="hidden lg:inline text-[10px] text-slate-400 font-medium">Upload an artifact below to start an investigation</span>
                  <Link to="/orchestrator" className="flex-1 sm:flex-none text-center bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-200 text-xs font-bold py-2 px-4 rounded-lg hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors flex items-center justify-center gap-2">
                    <span className="material-symbols-outlined text-sm">account_tree</span> View Trace
                  </Link>
                </div>
              </div>

              {/* Phase 2: Incident Response Upload Zone */}
              <div
                className={`mx-6 mt-0 mb-4 border-2 border-dashed rounded-xl p-4 transition-all text-center cursor-pointer relative ${isDragging ? 'border-primary bg-primary/10 scale-[1.01]' : 'border-slate-300 dark:border-slate-700 hover:border-primary/50 hover:bg-slate-50 dark:hover:bg-slate-800/30'}`}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onDrop={async (e) => {
                  e.preventDefault();
                  setIsDragging(false);
                  const file = e.dataTransfer.files[0];
                  if (!file) return;
                  setUploadStatus(`Uploading ${file.name}...`);
                  const res = await uploadFile(file);
                  if (res && res.report_id) {
                    setUploadStatus(`✓ IR triggered: ${res.report_id}`);
                    setTimeout(() => setUploadStatus(null), 5000);
                  } else {
                    setUploadStatus('✗ Upload failed');
                    setTimeout(() => setUploadStatus(null), 3000);
                  }
                }}
                onClick={() => document.getElementById('file-upload-input')?.click()}
              >
                <input id="file-upload-input" type="file" accept=".eml,.json,.csv,.txt" className="hidden" onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (!file) return;
                  setUploadStatus(`Uploading ${file.name}...`);
                  const res = await uploadFile(file);
                  if (res && res.report_id) {
                    setUploadStatus(`✓ IR triggered: ${res.report_id}`);
                    setTimeout(() => setUploadStatus(null), 5000);
                  } else {
                    setUploadStatus('✗ Upload failed');
                    setTimeout(() => setUploadStatus(null), 3000);
                  }
                  e.target.value = '';
                }} />
                <div className="flex items-center justify-center gap-3">
                  <div className={`size-10 rounded-lg flex items-center justify-center transition-colors ${isDragging ? 'bg-primary text-white' : 'bg-slate-100 dark:bg-slate-800 text-slate-400'}`}>
                    <span className="material-symbols-outlined">upload_file</span>
                  </div>
                  <div className="text-left">
                    <p className="text-xs font-bold text-slate-700 dark:text-slate-200">
                      {uploadStatus || 'Phase 2: Incident Response — Drag & Drop Evidence'}
                    </p>
                    <p className="text-[10px] text-slate-400">Upload .eml, .json, or .csv files for manual forensic investigation</p>
                  </div>
                  <span className="hidden sm:inline-block px-2 py-0.5 bg-amber-100 dark:bg-amber-900/30 text-amber-600 text-[9px] font-bold rounded uppercase">Manual</span>
                </div>
              </div>

              <div className="p-6">
                <h4 className="text-sm font-bold mb-4 flex items-center gap-2">
                  <span className="material-symbols-outlined text-primary text-base">psychology</span>
                  Autonomous Reasoning Trace
                  <span className="text-[10px] text-slate-400 font-normal ml-auto">Click a step to expand details</span>
                </h4>

                <div className="space-y-4 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-px before:bg-slate-200 dark:before:bg-slate-800">
                  {traces.length > 0 ? traces.map((trace, i) => {
                    const isExpanded = expandedTraceId === trace.id;
                    const details = getTraceDetails(trace);
                    const isSynthesis = trace.source.toLowerCase().includes('synthes');
                    const hasDetails = details && (details.findings.length > 0 || details.iocs.length > 0 || details.final_report);
                    const isAgent = ['Email Analyst', 'Forensic Analyst', 'Threat Intel', 'Synthesis'].some(a => trace.source.includes(a));

                    return (
                      <div key={trace.id} className="relative group animate-fade-in">
                        <div
                          className={`flex gap-4 cursor-pointer`}
                          onClick={() => isAgent ? setExpandedTraceId(isExpanded ? null : trace.id) : null}
                        >
                          <div className="size-6 rounded-full bg-slate-100 dark:bg-slate-800 border-2 border-white dark:border-slate-900 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                            <div className={`size-1.5 rounded-full ${i === traces.length - 1 && isRunning ? 'bg-primary animate-ping' : 'bg-primary'}`}></div>
                          </div>
                          <div className={`flex-1 p-3 rounded-lg border transition-all ${isExpanded ? 'bg-primary/5 border-primary/30 shadow-sm shadow-primary/10' : 'bg-slate-50 dark:bg-slate-800/40 border-slate-100 dark:border-slate-800 hover:border-primary/30'}`}>
                            <div className="flex justify-between items-center mb-1">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-primary">{trace.source}</span>
                                {isAgent && (
                                  <span className="material-symbols-outlined text-[12px] text-slate-400 transition-transform" style={{ transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)' }}>expand_more</span>
                                )}
                                {hasDetails && !isExpanded && !isSynthesis && (
                                  <span className="text-[9px] font-bold bg-amber-100 dark:bg-amber-900/30 text-amber-600 px-1.5 py-0.5 rounded">{details!.findings.length} findings</span>
                                )}
                                {hasDetails && !isExpanded && isSynthesis && (
                                  <span className="text-[9px] font-bold bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 px-1.5 py-0.5 rounded">Report Ready</span>
                                )}
                              </div>
                              <span className="text-[10px] text-slate-400">{new Date(trace.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-sm text-slate-600 dark:text-slate-300">{trace.description}</p>
                          </div>
                        </div>

                        {/* ═══ EXPANDED DETAIL PANEL ═══ */}
                        {isExpanded && details && (
                          <div className="ml-10 mt-2 bg-slate-900 rounded-lg border border-slate-700 overflow-hidden animate-fade-in shadow-inner">
                            <div className="p-3 border-b border-slate-800 flex items-center gap-2 text-emerald-400">
                              <span className="material-symbols-outlined text-sm">terminal</span>
                              <span className="text-[10px] font-bold uppercase tracking-widest">Agent Output — {trace.source}</span>
                            </div>
                            <div className="p-3 space-y-3">
                              {/* Synthesis Output */}
                              {isSynthesis && details.final_report && (
                                <div className="bg-slate-800/60 rounded-lg p-3 border border-slate-700">
                                  <div className="flex justify-between items-start mb-2">
                                    <span className="text-xs font-bold text-slate-200 uppercase tracking-widest">Executive Summary Generated</span>
                                    {details.risk_score !== undefined && (
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${details.risk_score >= 0.8 ? 'bg-red-900/60 text-red-400' :
                                          details.risk_score >= 0.5 ? 'bg-orange-900/60 text-orange-400' :
                                            'bg-green-900/60 text-green-400'
                                        }`}>
                                        Risk Score: {(details.risk_score * 100).toFixed(0)}%
                                      </span>
                                    )}
                                  </div>
                                  <div className="prose prose-invert prose-sm max-w-none text-slate-300 leading-relaxed font-sans">
                                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{details.final_report}</ReactMarkdown>
                                  </div>
                                </div>
                              )}

                              {/* Findings */}
                              {!isSynthesis && details.findings.length > 0 && details.findings.map((f: any, fi: number) => (
                                <div key={fi} className="bg-slate-800/60 rounded-lg p-3 border border-slate-700">
                                  <div className="flex justify-between items-start mb-1.5">
                                    <span className="text-xs font-bold text-slate-200">{f.finding_type || f.mitre_tactic || 'Detection'}</span>
                                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${f.severity === 'CRITICAL' ? 'bg-red-900/60 text-red-400' :
                                        f.severity === 'HIGH' ? 'bg-orange-900/60 text-orange-400' :
                                          f.severity === 'MEDIUM' ? 'bg-amber-900/60 text-amber-400' :
                                            'bg-slate-700 text-slate-400'
                                      }`}>{f.severity}</span>
                                  </div>
                                  <p className="text-[11px] text-slate-400 leading-relaxed mb-2">{f.description?.substring(0, 300)}</p>
                                  <div className="flex gap-3 text-[9px]">
                                    {f.mitre_tactic && <span className="text-indigo-400 font-bold">MITRE: {f.mitre_tactic}</span>}
                                    {f.evidence?.confidence_score && <span className="text-emerald-400 font-bold">Confidence: {(f.evidence.confidence_score * 100).toFixed(0)}%</span>}
                                    {f.evidence?.anomaly_score !== undefined && <span className="text-amber-400 font-bold">Anomaly: {f.evidence.anomaly_score.toFixed(2)}</span>}
                                    {f.evidence?.has_sigma_rule && <span className="text-cyan-400 font-bold flex items-center gap-0.5"><span className="material-symbols-outlined text-[10px]">rule</span>Sigma Rule</span>}
                                  </div>
                                </div>
                              ))}

                              {!isSynthesis && details.findings.length === 0 && (
                                <div className="text-[11px] text-slate-500 text-center py-2">No specific findings from this agent</div>
                              )}

                              {/* IOCs */}
                              {details.iocs.length > 0 && (
                                <div>
                                  <p className="text-[10px] font-bold text-rose-400 uppercase tracking-wider mb-1.5">IOCs Extracted</p>
                                  <div className="flex flex-wrap gap-1.5">
                                    {details.iocs.map((ioc: any, ii: number) => (
                                      <span key={ii} className="bg-rose-900/30 text-rose-400 text-[10px] font-mono font-bold px-2 py-1 rounded border border-rose-800/50">
                                        [{ioc.ioc_type}] {ioc.value}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  }) : (
                    <div className="text-center p-4 text-slate-500">No traces available. Trigger an investigation above to start.</div>
                  )}

                  {report?.final_report && (
                    <div className="flex flex-col gap-4 mt-6">
                      <div className="flex gap-4 relative group">
                        <div className="size-6 rounded-full bg-slate-100 dark:bg-slate-800 border-2 border-white dark:border-slate-900 flex items-center justify-center z-10 group-hover:scale-110 transition-transform">
                          <div className="size-1.5 rounded-full bg-green-500"></div>
                        </div>
                        <div className="flex-1 bg-primary/10 border border-primary/20 p-4 rounded-lg ring-1 ring-primary/30 shadow-sm shadow-primary/10">
                          <div className="flex justify-between items-center mb-3">
                            <span className="text-sm font-bold text-primary flex items-center gap-2">
                              <span className="material-symbols-outlined text-base">verified_user</span>
                              Response Orchestrator
                            </span>
                            <span className="text-[10px] text-primary/80 font-bold bg-primary/20 px-2 py-1 rounded tracking-wider uppercase">Final Verdict</span>
                          </div>
                          <div className="prose prose-sm xl:prose-base prose-slate dark:prose-invert max-w-none leading-relaxed text-slate-800 dark:text-slate-200">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.final_report}</ReactMarkdown>
                          </div>

                          {/* HiTL Actions (local UI state only — no feedback endpoint in Vigil v1) */}
                          <div className="mt-4 pt-4 border-t border-primary/20 flex flex-wrap gap-2">
                            <button onClick={() => setShowExplain(!showExplain)} className="bg-slate-800 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-slate-700 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">psychology</span> Explain Verdict
                            </button>
                            <button onClick={() => handleHiTLAction('Approved Mitigation')} className="bg-emerald-600 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-emerald-700 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">check_circle</span> Approve
                            </button>
                            <button onClick={() => handleHiTLAction('Marked False Positive')} className="bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-slate-300 dark:hover:bg-slate-600 transition-colors">
                              <span className="material-symbols-outlined text-[14px]">cancel</span> False Positive
                            </button>
                            <button onClick={() => handleHiTLAction('Escalated to Tier 3')} className="bg-rose-600 text-white text-xs font-bold py-1.5 px-3 rounded flex items-center gap-1 hover:bg-rose-700 transition-colors ml-auto">
                              <span className="material-symbols-outlined text-[14px]">priority_high</span> Escalate
                            </button>
                          </div>
                        </div>
                      </div>

                      {/* ═══ SOAR ACTION SIMULATION ═══ */}
                      {soarActions && (
                        <div className="ml-10 bg-slate-900 rounded-lg border border-slate-700 overflow-hidden animate-fade-in shadow-lg">
                          <div className="p-3 border-b border-slate-800 flex items-center gap-2 bg-emerald-900/20">
                            <span className="material-symbols-outlined text-emerald-400 text-sm">rocket_launch</span>
                            <span className="text-[10px] font-bold uppercase tracking-widest text-emerald-400">SOAR — Automated Response Actions</span>
                          </div>
                          <div className="p-3 space-y-2">
                            {soarActions.map((action, ai) => (
                              <div key={ai} className={`flex items-center gap-3 p-2.5 rounded-lg transition-all duration-500 ${action.status === 'done' ? 'bg-emerald-900/20 border border-emerald-800/50' :
                                  action.status === 'running' ? 'bg-primary/10 border border-primary/30' :
                                    'bg-slate-800/40 border border-slate-800'
                                }`}>
                                <div className={`size-7 rounded-lg flex items-center justify-center transition-all ${action.status === 'done' ? 'bg-emerald-500/20 text-emerald-400' :
                                    action.status === 'running' ? 'bg-primary/20 text-primary animate-pulse' :
                                      'bg-slate-800 text-slate-500'
                                  }`}>
                                  {action.status === 'done' ? (
                                    <span className="material-symbols-outlined text-sm">check</span>
                                  ) : action.status === 'running' ? (
                                    <span className="material-symbols-outlined text-sm animate-spin">autorenew</span>
                                  ) : (
                                    <span className="material-symbols-outlined text-sm">{action.icon}</span>
                                  )}
                                </div>
                                <span className={`text-xs font-bold flex-1 ${action.status === 'done' ? 'text-emerald-300' :
                                    action.status === 'running' ? 'text-white' :
                                      'text-slate-500'
                                  }`}>{action.label}</span>
                                <span className={`text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${action.status === 'done' ? 'bg-emerald-500/20 text-emerald-400' :
                                    action.status === 'running' ? 'bg-primary/20 text-primary' :
                                      'text-slate-600'
                                  }`}>{action.status === 'done' ? 'COMPLETED' : action.status === 'running' ? 'RUNNING...' : 'QUEUED'}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Explainability View */}
                      {showExplain && (
                        <div className="ml-10 bg-slate-900 text-slate-300 p-4 rounded-lg font-mono text-xs border border-slate-700 animate-fade-in shadow-inner">
                          <div className="flex items-center gap-2 mb-3 text-emerald-400 border-b border-slate-800 pb-2 font-bold uppercase tracking-wider text-[10px]">
                            <span className="material-symbols-outlined text-sm">code_blocks</span> Semantic Highlighting (Raw Input)
                          </div>
                          <p className="leading-relaxed whitespace-pre-wrap">
                            {(() => {
                              const ePayload = report?.event_payload || {};
                              // If it's a raw email
                              const rawEml = ePayload.detail?.raw_eml || ePayload.detail?.eml_content || ePayload.raw_eml || '';
                              if (rawEml) {
                                return rawEml.split(/\s+/).map((word: string, i: number) => {
                                  const isIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(word);
                                  const isUrgent = /urgent|suspended|24 hours|verify|password|login/i.test(word);
                                  const isLink = /http[s]?:\/\//i.test(word);

                                  if (isIP) return <span key={i} onClick={() => { setSelectedIP(word); setShowIntel(true); }} className="bg-red-900/50 text-red-400 px-1 rounded font-bold cursor-pointer hover:bg-emerald-500 hover:text-white transition-all mx-0.5">{word} </span>;
                                  if (isLink) return <span key={i} className="bg-red-900/50 text-red-400 px-1 rounded underline font-bold mx-0.5" title="Suspicious Link">{word} </span>;
                                  if (isUrgent) return <span key={i} className="bg-yellow-900/50 text-yellow-500 px-1 rounded font-bold mx-0.5">{word} </span>;
                                  return word + ' ';
                                });
                              }

                              // If it's a JSON log payload (e.g. CloudTrail)
                              if (ePayload.detail || Object.keys(ePayload).length > 0) {
                                const jsonStr = JSON.stringify(ePayload.detail || ePayload, null, 2);
                                return jsonStr.split('\n').map((line: string, i: number) => {
                                  if (line.includes('"userName":') || line.includes('"principalId":')) return <span key={i} className="text-yellow-500">{line}<br /></span>;
                                  if (line.includes('"sourceIPAddress":')) return <span key={i} className="text-red-400 font-bold">{line}<br /></span>;
                                  if (line.includes('"eventName":')) return <span key={i} className="text-indigo-400">{line}<br /></span>;
                                  return <span key={i}>{line}<br /></span>;
                                });
                              }

                              return <span className="text-slate-500">No raw input data available.</span>;
                            })()}
                          </p>
                          <div className="mt-4 pt-3 border-t border-slate-800 flex gap-4 text-[10px] uppercase font-bold tracking-wider">
                            <span className="flex items-center gap-1 text-red-400 transition-transform hover:scale-105 cursor-help" title="Click technical artifacts above for deep intel"><span className="size-2 rounded-full bg-red-500 mix-blend-screen"></span> High Risk Indicator</span>
                            <span className="flex items-center gap-1 text-yellow-500"><span className="size-2 rounded-full bg-yellow-500 mix-blend-screen"></span> Social Engineering Tone</span>
                          </div>
                        </div>
                      )}

                      {/* Audit Trail */}
                      {auditTrail.length > 0 && (
                        <div className="ml-10 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden animate-fade-in shadow-sm">
                          <div className="bg-slate-50 dark:bg-slate-800/50 p-2.5 text-xs font-bold text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2 uppercase tracking-wider">
                            <span className="material-symbols-outlined text-[14px]">history</span> Human-in-the-Loop Audit Trail
                          </div>
                          <table className="w-full text-left text-xs">
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                              {auditTrail.map((log, idx) => (
                                <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
                                  <td className="p-2.5 text-slate-400 w-24 border-r border-slate-100 dark:border-slate-800">{log.time}</td>
                                  <td className="p-2.5 font-mono text-primary w-32 border-r border-slate-100 dark:border-slate-800">{log.user}</td>
                                  <td className="p-2.5 font-medium text-slate-700 dark:text-slate-200 flex items-center gap-2">
                                    <span className="material-symbols-outlined text-[14px] text-primary">done</span>
                                    {log.action}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Right Sidebar */}
          <div className="lg:col-span-4 space-y-6">
            {/* Alert Feed */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-900/50">
                <h4 className="font-bold text-sm">Findings</h4>
                <Link to="/orchestrator" className="text-xs text-primary font-bold hover:underline">See Details</Link>
              </div>
              <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-64 overflow-y-auto">
                {report?.findings && report.findings.length > 0 ? report.findings.map((f, i) => (
                  <div key={i} className="p-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group">
                    <div className="flex gap-3">
                      <span className={`size-2 rounded-full mt-1.5 group-hover:scale-125 transition-transform ${String(f.severity).toLowerCase() === 'high' || String(f.severity).toLowerCase() === 'critical' ? 'bg-red-500' : 'bg-orange-500'}`}></span>
                      <div className="flex-1">
                        <p className="text-sm font-bold text-slate-800 dark:text-slate-200 group-hover:text-primary transition-colors">{f.finding_type || f.mitre_tactic || 'Security Finding'}</p>
                        <p className="text-xs text-slate-500 mt-0.5 truncate">{f.description}</p>
                        <p className="text-[10px] text-slate-400 mt-2 font-medium bg-slate-100 dark:bg-slate-800 inline-block px-2 py-0.5 rounded">Detected by {f.agent}</p>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="p-4 text-center text-sm text-slate-500">No active findings</div>
                )}
              </div>
            </div>

            {/* Agent Status List */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
              <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50">
                <h4 className="font-bold text-sm">Autonomous Agents</h4>
              </div>
              <div className="p-4 space-y-4">
                {nodes.filter(n => n.type !== 'supervisor').map((node) => {
                  let statusColor = 'bg-slate-100 dark:bg-slate-800 text-slate-500';
                  if (node.status === 'running') statusColor = 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600';
                  else if (node.status === 'completed') {
                    const hasThreat = report?.findings?.some((f: any) => f.agent.includes(node.id) && (f.severity === 'CRITICAL' || f.severity === 'HIGH'));
                    statusColor = hasThreat ? 'bg-red-100 dark:bg-red-900/30 text-red-600' : 'bg-green-100 dark:bg-green-900/30 text-green-600';
                  }

                  return (
                    <div key={node.id} className="flex items-center justify-between group hover:bg-slate-50 dark:hover:bg-slate-800/30 p-2 -mx-2 rounded-lg transition-colors cursor-pointer">
                      <div className="flex items-center gap-3">
                        <div className={`size-8 rounded flex items-center justify-center transition-colors ${statusColor}`}>
                          <span className="material-symbols-outlined text-sm">{node.icon}</span>
                        </div>
                        <span className={`text-xs font-medium transition-colors ${node.status === 'running' ? 'text-primary' : 'group-hover:text-primary'}`}>{node.name}</span>
                      </div>
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase ${statusColor} ${node.status === 'running' ? 'animate-pulse' : ''}`}>
                        {node.status}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Quick Actions Card */}
            <div className="bg-primary p-6 rounded-xl text-white shadow-lg shadow-primary/20 bg-[url('https://www.transparenttextures.com/patterns/cubes.png')] hover:bg-primary/95 transition-colors">
              <h4 className="font-bold text-sm mb-2 flex items-center gap-2">
                <span className="material-symbols-outlined text-white">warning</span>
                SOC Readiness
              </h4>
              <p className="text-white/90 text-xs mb-4 leading-relaxed font-medium">Your infrastructure is currently under high stress. Automation is handling 100% of EventBridge alerts.</p>
              <div className="grid grid-cols-2 gap-2">
                <button onClick={() => alert('Initiating Full Lockdown... All non-essential access blocked.')} className="bg-white/10 hover:bg-white/20 transition-colors py-2 rounded text-[10px] font-bold border border-white/20 flex items-center justify-center gap-1">
                  <span className="material-symbols-outlined text-[14px]">lock</span> Full Lockdown
                </button>
                <button onClick={() => {
                  if (report) {
                    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
                    const dlAnchorElem = document.createElement('a');
                    dlAnchorElem.setAttribute("href", dataStr);
                    dlAnchorElem.setAttribute("download", `${report.report_id}.json`);
                    dlAnchorElem.click();
                  } else {
                    alert("No report to export!");
                  }
                }} className="bg-white/10 hover:bg-white/20 transition-colors py-2 rounded text-[10px] font-bold border border-white/20 flex items-center justify-center gap-1">
                  <span className="material-symbols-outlined text-[14px]">download</span> Export Report
                </button>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Threat Intel Side-drawer */}
      {showIntel && (
        <div className="fixed inset-0 z-[100] flex justify-end">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={() => setShowIntel(false)}></div>
          <div className="relative w-96 bg-white dark:bg-slate-900 h-full shadow-2xl border-l border-slate-200 dark:border-slate-800 flex flex-col animate-slide-in-right">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-primary text-white">
              <h4 className="font-bold text-sm uppercase tracking-widest flex items-center gap-2">
                <span className="material-symbols-outlined text-lg">public-off</span> Deep Threat Intel
              </h4>
              <button onClick={() => setShowIntel(false)} className="hover:bg-white/20 p-1 rounded-md transition-colors">
                <span className="material-symbols-outlined text-md">close</span>
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="flex flex-col items-center gap-2 pb-6 border-b border-slate-100 dark:border-slate-800">
                <span className="text-4xl font-black text-slate-800 dark:text-white tracking-tight">{selectedIP}</span>
                <span className="px-3 py-1 bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400 rounded-full text-[10px] font-bold uppercase tracking-widest border border-rose-200 dark:border-rose-800">High Risk Asset</span>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-100 dark:border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Reputation Score</p>
                  <p className="text-2xl font-black text-rose-500">92/100</p>
                </div>
                <div className="bg-slate-50 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-100 dark:border-slate-800">
                  <p className="text-[10px] text-slate-500 uppercase font-bold mb-1">Tor Exit Node</p>
                  <p className="text-2xl font-black text-emerald-500 tracking-tighter">YES</p>
                </div>
              </div>

              <div className="space-y-4">
                <h5 className="text-[10px] text-slate-500 uppercase font-bold tracking-widest flex items-center gap-2">
                  <span className="size-1.5 rounded-full bg-primary"></span>
                  Actor Attribution
                </h5>
                <div className="p-4 bg-slate-900 rounded-xl border border-slate-800">
                  <p className="text-emerald-400 font-bold text-sm mb-1">COZY BEAR (APT29)</p>
                  <p className="text-slate-400 text-xs leading-relaxed">Infrastructure historically associated with Russian-backed cyber espionage campaigns targeting financial institutions.</p>
                </div>
              </div>

              <div className="space-y-4">
                <h5 className="text-[10px] text-slate-500 uppercase font-bold tracking-widest flex items-center gap-2">
                  <span className="size-1.5 rounded-full bg-primary"></span>
                  Geo-Location
                </h5>
                <div className="h-32 bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden relative group">
                  <div className="absolute inset-0 bg-gradient-to-br from-slate-700 to-slate-900"></div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="material-symbols-outlined text-primary text-4xl animate-bounce">location_on</span>
                  </div>
                </div>
                <p className="text-[10px] text-slate-500 text-center font-mono">Russia, Moscow - 55.7558° N, 37.6173° E</p>
              </div>
            </div>
            <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-800">
              <button onClick={() => handleHiTLAction(`Blocked IP ${selectedIP}`)} className="w-full bg-rose-600 text-white font-bold py-3 rounded-xl hover:bg-rose-700 transition-colors flex items-center justify-center gap-2 shadow-lg shadow-rose-900/20 text-sm">
                <span className="material-symbols-outlined">block</span> Blacklist IP Immediately
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FP Feedback Modal */}
      {showFPFeedback && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-md" onClick={() => setShowFPFeedback(false)}></div>
          <div className="relative max-w-md w-full bg-white dark:bg-slate-900 rounded-3xl shadow-2xl overflow-hidden animate-zoom-in border border-slate-200 dark:border-slate-800">
            <div className="p-8 text-center space-y-4">
              <div className="size-16 bg-orange-100 dark:bg-orange-900/30 text-orange-600 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="material-symbols-outlined text-3xl">psychology_alt</span>
              </div>
              <h3 className="text-xl font-black tracking-tight">RLHF Feedback Loop</h3>
              <p className="text-slate-500 dark:text-slate-400 text-sm">Help the model learn. Why is this incident a False Positive?</p>

              <div className="grid grid-cols-1 gap-2 py-4">
                {['Legitimate User Behavior', 'Incorrect Pattern Match', 'Test Incident / Drills', 'Outdated Global Feed'].map((reason) => (
                  <button
                    key={reason}
                    onClick={() => {
                      handleHiTLAction(`FP Reason: ${reason}`);
                      setShowFPFeedback(false);
                    }}
                    className="text-left p-4 rounded-2xl border border-slate-100 dark:border-slate-800 hover:border-primary hover:bg-primary/5 transition-all group flex items-center justify-between"
                  >
                    <span className="text-sm font-bold text-slate-700 dark:text-slate-300 group-hover:text-primary transition-colors">{reason}</span>
                    <span className="material-symbols-outlined text-transparent group-hover:text-primary transition-all">chevron_right</span>
                  </button>
                ))}
              </div>

              <button onClick={() => setShowFPFeedback(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs font-bold transition-colors">
                Skip feedback loop
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
