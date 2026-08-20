import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { Report } from '../types';
import { fetchLatestReport, fetchNodes } from '../services/api';

export const GraphView = () => {
  const [report, setReport] = useState<Report | null>(null);
  const [nodes, setNodes] = useState<any[]>([]);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  useEffect(() => {
    const loadData = async () => {
      const data = await fetchLatestReport();
      if (data) setReport(data);
      const nodesData = await fetchNodes();
      setNodes(nodesData);
    };
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const getNodeStatus = (id: string) => {
    return nodes.find(n => n.id === id)?.status || 'idle';
  };

  const getPathColor = (nodeId: string) => {
    const status = getNodeStatus(nodeId);
    if (status === 'running') return "text-primary stroke-current animate-pulse stroke-[0.5]";
    if (status === 'completed') return "text-emerald-500 stroke-current stroke-[0.3]";
    return "text-slate-300 dark:text-slate-700 stroke-current stroke-[0.15] opacity-50";
  };

  return (
    <section className="flex-1 relative flex flex-col p-6 bg-slate-50 dark:bg-background-dark/30 overflow-hidden">
      <div className="flex items-center justify-between mb-8 z-10">
        <div>
          <h3 className="text-2xl font-black text-slate-900 dark:text-slate-100 tracking-tight">Orchestration Graph</h3>
          <p className="text-slate-500 dark:text-slate-400 text-sm">Real-time state transitions and task delegation</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => window.location.reload()} className="bg-white dark:bg-primary/10 border border-slate-200 dark:border-primary/20 px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-primary/20 transition-colors">
            <span className="material-symbols-outlined text-sm">refresh</span> Reset View
          </button>
          <Link to="/" title="Upload an artifact on the Dashboard to start a run" className="bg-primary hover:bg-primary/90 shadow-lg shadow-primary/20 text-white px-4 py-2 rounded-lg text-sm font-bold flex items-center gap-2 transition-colors">
            <span className="material-symbols-outlined text-sm">upload_file</span> New Investigation
          </Link>
        </div>
      </div>
      
      {/* Visualization Canvas */}
      <div className="flex-1 relative border border-slate-200 dark:border-primary/10 rounded-2xl bg-white dark:bg-background-dark node-connector overflow-hidden shadow-inner min-h-[500px]">
        {/* SVG Connections (Visualizing the flow) */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none" preserveAspectRatio="none" viewBox="0 0 100 100">
          <defs>
            <marker id="arrowhead-primary" markerHeight="7" markerWidth="10" orient="auto" refX="5" refY="3.5">
              <polygon fill="currentColor" points="0 0, 10 3.5, 0 7" className="text-primary"></polygon>
            </marker>
            <marker id="arrowhead-slate" markerHeight="7" markerWidth="10" orient="auto" refX="5" refY="3.5">
              <polygon fill="currentColor" points="0 0, 10 3.5, 0 7" className="text-slate-300 dark:text-slate-700"></polygon>
            </marker>
            <marker id="arrowhead-emerald" markerHeight="7" markerWidth="10" orient="auto" refX="5" refY="3.5">
              <polygon fill="currentColor" points="0 0, 10 3.5, 0 7" className="text-emerald-500"></polygon>
            </marker>
          </defs>
          {/* Supervisor to Agents */}
          <line markerEnd={`url(#arrowhead-${getNodeStatus('email') === 'running' ? 'primary' : getNodeStatus('email') === 'completed' ? 'emerald' : 'slate'})`} className={getPathColor('email')} x1="50" x2="20" y1="22" y2="43" vectorEffect="non-scaling-stroke"></line>
          <line markerEnd={`url(#arrowhead-${getNodeStatus('forensic') === 'running' ? 'primary' : getNodeStatus('forensic') === 'completed' ? 'emerald' : 'slate'})`} className={getPathColor('forensic')} x1="50" x2="50" y1="22" y2="43" vectorEffect="non-scaling-stroke"></line>
          <line markerEnd={`url(#arrowhead-${getNodeStatus('threat') === 'running' ? 'primary' : getNodeStatus('threat') === 'completed' ? 'emerald' : 'slate'})`} className={getPathColor('threat')} x1="50" x2="80" y1="22" y2="43" vectorEffect="non-scaling-stroke"></line>
        {/* Shared State Connections */}
        <path d="M 20 55 Q 20 78 50 78" fill="none" className={getPathColor('email')} strokeDasharray="5,5" vectorEffect="non-scaling-stroke"></path>
        <path d="M 50 55 Q 50 78 50 78" fill="none" className={getPathColor('forensic')} strokeDasharray="5,5" vectorEffect="non-scaling-stroke"></path>
        <path d="M 80 55 Q 80 78 50 78" fill="none" className={getPathColor('threat')} strokeDasharray="5,5" vectorEffect="non-scaling-stroke"></path>
          {/* Return to Supervisor */}
          <path d="M 50 75 L 10 75 L 10 22 L 40 22" fill="none" markerEnd={`url(#arrowhead-${getNodeStatus('supervisor') === 'running' ? 'primary' : 'slate'})`} className={getPathColor('supervisor')} strokeDasharray="3,3" vectorEffect="non-scaling-stroke"></path>
        </svg>

        {/* Nodes */}
        {/* Supervisor Node */}
        <div className="absolute top-[12%] sm:top-[15%] left-1/2 -translate-x-1/2 z-20">
          <div className={`bg-primary p-1 rounded-xl shadow-2xl group hover:scale-105 transition-all duration-300 ${getNodeStatus('supervisor') === 'running' ? 'shadow-primary/60 ring-4 ring-primary/30 animate-pulse' : 'shadow-primary/40'}`}>
            <div className="bg-background-dark px-6 py-4 rounded-lg flex items-center gap-4">
              <div className="size-12 rounded-full bg-primary/20 flex items-center justify-center">
                <span className="material-symbols-outlined text-primary text-3xl">psychology</span>
              </div>
              <div>
                <h4 className="text-white font-bold">Supervisor</h4>
                <span className="text-[10px] uppercase bg-primary text-white px-2 py-0.5 rounded-full font-black">Orchestrator</span>
              </div>
            </div>
          </div>
        </div>

        {/* Agent Nodes Row */}
        <div className="absolute top-[48%] -translate-y-1/2 left-0 w-full flex justify-between px-[10%] sm:px-[15%] z-20">
          {/* Email Analyst */}
          <div onClick={() => setSelectedNode('Email Analyst')} className={`bg-white dark:bg-slate-800 border-2 p-4 rounded-xl shadow-lg w-48 transition-all group cursor-pointer hover:-translate-y-1 transform duration-200 ${getNodeStatus('email') === 'running' ? 'border-primary ring-4 ring-primary/20 shadow-primary/30' : 'border-slate-200 dark:border-primary/20 hover:border-primary'}`}>
            <div className="flex items-center gap-3 mb-2">
              <span className={`material-symbols-outlined ${getNodeStatus('email') === 'running' ? 'text-primary animate-pulse' : 'text-slate-400 group-hover:text-primary'}`}>mail</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Email Analyst</span>
            </div>
            <p className="text-[11px] text-slate-500">{getNodeStatus('email') === 'running' ? 'Analyzing email headers & phishing signals...' : getNodeStatus('email') === 'completed' ? 'Email analysis complete.' : 'Awaiting email event...'}</p>
            <div className="mt-3 flex gap-1">
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('email') === 'completed' ? 'bg-green-500' : getNodeStatus('email') === 'running' ? 'bg-primary animate-pulse' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('email') === 'completed' ? 'bg-green-500' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
            </div>
          </div>

          {/* Tier-1 Filter */}
          <div onClick={() => setSelectedNode('Tier-1 Filter')} className={`bg-white dark:bg-slate-800 border-2 p-4 rounded-xl shadow-lg w-48 transition-all group cursor-pointer hover:-translate-y-1 transform duration-200 relative ${getNodeStatus('forensic') === 'running' ? 'border-primary ring-4 ring-primary/20 shadow-primary/30' : 'border-slate-200 dark:border-primary/20 hover:border-primary'}`}>
            {getNodeStatus('forensic') === 'running' && (
              <div className="absolute -top-2 -right-2 flex size-4 items-center justify-center rounded-full bg-primary animate-bounce">
                  <span className="text-[8px] text-white font-bold">!</span>
              </div>
            )}
            <div className="flex items-center gap-3 mb-2">
              <span className={`material-symbols-outlined ${getNodeStatus('forensic') === 'running' ? 'text-primary animate-pulse' : 'text-slate-400 group-hover:text-primary'}`}>filter_alt</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Tier-1 Filter</span>
            </div>
            <p className="text-[11px] text-slate-500">{getNodeStatus('forensic') === 'running' ? 'PII scrubbing, rule checks & ONNX scoring...' : getNodeStatus('forensic') === 'completed' ? 'Tier-1 filtering complete.' : 'Awaiting artifact...'}</p>
            <div className="mt-3 flex gap-1">
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('forensic') === 'completed' ? 'bg-green-500' : getNodeStatus('forensic') === 'running' ? 'bg-primary animate-pulse' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('forensic') === 'completed' ? 'bg-green-500' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
            </div>
          </div>

          {/* Threat Intel */}
          <div onClick={() => setSelectedNode('Threat Intel')} className={`bg-white dark:bg-slate-800 border-2 p-4 rounded-xl shadow-lg w-48 transition-all group cursor-pointer hover:-translate-y-1 transform duration-200 ${getNodeStatus('threat') === 'running' ? 'border-primary ring-4 ring-primary/20 shadow-primary/30' : 'border-slate-200 dark:border-primary/20 hover:border-primary'}`}>
            <div className="flex items-center gap-3 mb-2">
              <span className={`material-symbols-outlined ${getNodeStatus('threat') === 'running' ? 'text-primary animate-pulse' : 'text-slate-400 group-hover:text-primary'}`}>public</span>
              <span className="font-bold text-sm text-slate-800 dark:text-slate-100">Threat Intel</span>
            </div>
            <p className="text-[11px] text-slate-500">{getNodeStatus('threat') === 'running' ? 'Querying VirusTotal & AbuseIPDB...' : getNodeStatus('threat') === 'completed' ? 'IOC reputation verified.' : 'Idle...'}</p>
            <div className="mt-3 flex gap-1">
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('threat') === 'completed' ? 'bg-green-500' : getNodeStatus('threat') === 'running' ? 'bg-primary animate-pulse' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
              <div className={`h-1 flex-1 rounded-full ${getNodeStatus('threat') === 'completed' ? 'bg-green-500' : 'bg-slate-200 dark:bg-slate-700'}`}></div>
            </div>
          </div>
        </div>

        {/* Shared State Hub */}
        <div onClick={() => setSelectedNode('Shared State')} className="absolute bottom-[12%] sm:bottom-[15%] left-1/2 -translate-x-1/2 w-80 z-20 hover:scale-[1.02] transition-transform duration-300 cursor-pointer">
          <div className="bg-slate-900 border border-primary/40 rounded-2xl p-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4 border-b border-white/10 pb-2">
              <span className="material-symbols-outlined text-primary">database</span>
              <h5 className="text-white font-bold text-sm">Shared State Hub</h5>
            </div>
            
            {report ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">Findings:</span>
                  <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded">{report.findings?.length || 0} Detected</span>
                </div>
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">IOCs:</span>
                  <span className="text-[10px] bg-primary/20 text-primary px-2 py-0.5 rounded">{report.iocs?.length || 0} Collected</span>
                </div>
                <div className="flex items-center justify-between group">
                  <span className="text-[10px] text-slate-400 font-mono group-hover:text-slate-300">Error Logs:</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${(report.error_logs?.length || 0) > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                    {(report.error_logs?.length || 0) > 0 ? `${report.error_logs?.length} Errors` : 'None'}
                  </span>
                </div>
              </div>
            ) : (
              <div className="flex justify-center p-2">
                 <span className="material-symbols-outlined animate-spin text-primary">autorenew</span>
              </div>
            )}
            
          </div>
        </div>

        {/* Deep Dive Overlay */}
        {selectedNode && (
          <div className="absolute top-0 right-0 bottom-0 w-80 bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl z-50 animate-fade-in flex flex-col">
            <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center bg-slate-50 dark:bg-slate-800/50">
              <h4 className="font-bold text-sm uppercase tracking-wider flex items-center gap-2 text-primary">
                <span className="material-symbols-outlined">analytics</span> {selectedNode}
              </h4>
              <button onClick={() => setSelectedNode(null)} className="hover:text-red-500 transition-colors p-1 bg-white dark:bg-slate-800 rounded-md border border-slate-200 dark:border-slate-700 shadow-sm">
                <span className="material-symbols-outlined text-sm">close</span>
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-6">
              {/* Dynamic Content Extraction */}
              {(() => {
                if (selectedNode === 'Shared State') {
                  // Show full shared state details
                  const allFindings = report?.findings || [];
                  const allIOCs = report?.iocs || [];
                  const allErrors = report?.error_logs || [];
                  const uniqueAgents = [...new Set(allFindings.map(f => f.agent))];
                  return (
                    <>
                      <div>
                        <h5 className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">bug_report</span> Findings ({allFindings.length})</h5>
                        {allFindings.length === 0 ? (
                          <p className="text-[10px] text-slate-400 italic">No findings yet — agents still processing...</p>
                        ) : (
                          <div className="space-y-2 max-h-48 overflow-y-auto">
                            {uniqueAgents.map(agent => (
                              <div key={agent}>
                                <p className="text-[9px] font-bold text-primary uppercase mb-1">{agent}</p>
                                {allFindings.filter(f => f.agent === agent).map((f, i) => (
                                  <div key={i} className="bg-slate-100 dark:bg-slate-950 p-2 rounded-md text-[9px] mb-1 border border-slate-200 dark:border-slate-800">
                                    <span className={`inline-block px-1.5 py-0.5 rounded text-[8px] font-bold mr-1 ${
                                      String(f.severity).toUpperCase() === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                                      String(f.severity).toUpperCase() === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                                      String(f.severity).toUpperCase() === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                                      'bg-green-500/20 text-green-400'
                                    }`}>{f.severity}</span>
                                    <span className="text-slate-600 dark:text-slate-400">{f.description?.substring(0, 80)}...</span>
                                  </div>
                                ))}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                      <div>
                        <h5 className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">shield</span> IOCs ({allIOCs.length})</h5>
                        {allIOCs.length === 0 ? (
                          <p className="text-[10px] text-slate-400 italic">No IOCs extracted yet.</p>
                        ) : (
                          <div className="space-y-1 max-h-32 overflow-y-auto">
                            {allIOCs.map((ioc, i) => (
                              <div key={i} className="flex items-center gap-2 text-[9px] bg-slate-100 dark:bg-slate-950 p-1.5 rounded border border-slate-200 dark:border-slate-800">
                                <span className="bg-primary/20 text-primary px-1.5 py-0.5 rounded font-bold">{ioc.ioc_type}</span>
                                <span className="text-slate-600 dark:text-slate-300 font-mono truncate">{ioc.value}</span>
                                <span className="text-slate-400 ml-auto text-[8px]">{ioc.source_agent}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                      {allErrors.length > 0 && (
                        <div>
                          <h5 className="text-[10px] font-bold text-red-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">error</span> Errors ({allErrors.length})</h5>
                          <div className="space-y-1 max-h-20 overflow-y-auto">
                            {allErrors.map((err: string, i: number) => (
                              <p key={i} className="text-[9px] text-red-400 bg-red-500/10 p-1.5 rounded">{typeof err === 'string' ? err : JSON.stringify(err)}</p>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  );
                }

                const agentId = selectedNode.split(' ')[0].toLowerCase();
                const agentFindings = report?.findings?.filter(f => f.agent.toLowerCase().includes(agentId)) || [];
                const agentIOCs = report?.iocs?.filter(i => i.source_agent.toLowerCase().includes(agentId)) || [];
                
                // Construct a dynamic input simulation based on report context
                const inputData = {
                  timestamp: report?.timestamp || new Date().toISOString(),
                  event_source: report?.event_type || 'unknown',
                  context: agentId === 'email' ? 'raw_eml + phishing_classifier' : agentId === 'tier-1' ? 'rules + PII scrubber + ONNX classifier' : 'virustotal + abuseipdb'
                };

                // Construct dynamic output from findings/IOCs
                const outputData = {
                  findings_count: agentFindings.length,
                  iocs_extracted: agentIOCs.map(i => i.value),
                  recommendation: agentFindings[0]?.description?.substring(0, 50) + '...' || 'No critical findings'
                };

                return (
                  <>
                    <div>
                      <h5 className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">input</span> Data Input (Live)</h5>
                      <div className="bg-slate-100 dark:bg-slate-950 p-3 rounded-lg text-[10px] font-mono whitespace-pre-wrap border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 shadow-inner">
                        {JSON.stringify(inputData, null, 2)}
                      </div>
                    </div>
                    <div className="flex justify-center -my-3 relative z-10">
                      <span className="material-symbols-outlined text-primary bg-white dark:bg-slate-900 rounded-full border border-slate-200 dark:border-slate-800 text-sm p-1 shadow-sm">arrow_downward</span>
                    </div>
                    <div>
                      <h5 className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">output</span> Extracted Output</h5>
                      <div className="bg-primary/5 dark:bg-primary/10 p-3 rounded-lg text-[10px] font-mono whitespace-pre-wrap border border-primary/20 text-slate-800 dark:text-slate-200 shadow-inner">
                        {JSON.stringify(outputData, null, 2)}
                      </div>
                    </div>
                  </>
                );
              })()}

              <div className="pt-6 border-t border-slate-200 dark:border-slate-800 mt-4">
                <h5 className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-2 flex items-center gap-1"><span className="material-symbols-outlined text-[14px]">timeline</span> Activity Sparkline</h5>
                <div className="h-10 flex items-end gap-[2px] opacity-70">
                   {[40, 70, 45, 90, 60, 100, 85, 30].map((h, i) => (
                      <div key={i} className={`flex-1 bg-primary rounded-t-sm transition-all duration-300 hover:opacity-100 ${getNodeStatus(selectedNode.split(' ')[0].toLowerCase()) === 'running' ? 'animate-pulse' : ''}`} style={{height: `${h}%`, animationDelay: `${i*100}ms`}}></div>
                   ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
