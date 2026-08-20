import { useEffect, useState } from 'react';
import type { TraceEvent } from '../types';
import { fetchTraces, fetchAgentLogs } from '../services/api';

export const RightPanel = ({ selectedAgentId, onClearSelection }: { selectedAgentId?: string | null, onClearSelection?: () => void }) => {
  const [traces, setTraces] = useState<TraceEvent[]>([]);
  const [agentLogs, setAgentLogs] = useState<any[]>([]);

  useEffect(() => {
    fetchTraces().then(setTraces);
    if (selectedAgentId) {
        fetchAgentLogs(selectedAgentId).then(setAgentLogs);
    }
    const interval = setInterval(() => {
      fetchTraces().then(setTraces);
      if (selectedAgentId) {
          fetchAgentLogs(selectedAgentId).then(setAgentLogs);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [selectedAgentId]);

  const getIconForType = (type: string) => {
    switch (type) {
      case 'delegation': return 'play_arrow';
      case 'artifact': return 'edit_document';
      case 'enrichment': return 'verified';
      case 'synthesis': return 'auto_fix_high';
      case 'error': return 'error';
      default: return 'circle';
    }
  };

  return (
    <aside className="w-full lg:w-80 border-l border-slate-200 dark:border-primary/10 p-6 flex flex-col gap-6 overflow-y-auto bg-white/50 dark:bg-transparent">
      {selectedAgentId ? (
        <div className="animate-fade-in flex flex-col h-full gap-4">
           <div className="flex items-center justify-between">
             <h4 className="text-sm font-bold uppercase tracking-wider text-primary flex items-center gap-2">
               <span className="material-symbols-outlined">memory</span>
               Agent Inspector
             </h4>
             {onClearSelection && (
               <button onClick={onClearSelection} className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 rounded-full hover:bg-slate-200 dark:hover:bg-slate-800 transition-colors">
                  <span className="material-symbols-outlined text-[18px]">close</span>
               </button>
             )}
           </div>
           
           <div className="bg-slate-900 rounded-xl border border-slate-700 p-4 overflow-y-auto font-mono text-[11px] text-emerald-400 flex-1 flex flex-col gap-3 shadow-inner">
             <div className="text-slate-500 border-b border-slate-800 pb-2 flex items-center gap-2">
               <span className="animate-pulse h-2 w-2 bg-emerald-500 rounded-full"></span>
               Connected to {selectedAgentId.replace('_', ' ').toUpperCase()} runtime...
             </div>
             
             {agentLogs.length === 0 ? (
               <div className="text-slate-500 italic mt-2">No activity logs recorded yet...</div>
             ) : (
               agentLogs.map((log, i) => (
                 <div key={i} className="flex flex-col gap-1 bg-slate-800/50 p-2 rounded border border-slate-700/50">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-500 shrink-0">[{new Date(log.ts).toISOString().split('T')[1].substring(0,8)}]</span>
                      <span className="text-slate-300 font-bold shrink-0">{log.action}</span>
                    </div>
                    <span className="text-slate-400 break-words pl-2 border-l-2 border-slate-700 text-[10px]">{log.detail}</span>
                 </div>
               ))
             )}
           </div>
        </div>
      ) : (
        <>
          <div>
            <h4 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Sequence Flow</h4>
            <div className="space-y-6 relative before:absolute before:left-[11px] before:top-2 before:bottom-2 before:w-[2px] before:bg-slate-200 dark:before:bg-primary/20">
              
              {traces.map((trace, idx) => (
                <div key={trace.id} className="flex gap-4 relative">
                  <div className={`size-6 rounded-full flex items-center justify-center z-10 ${
                    idx === 0 
                      ? 'bg-primary text-white' 
                      : 'bg-slate-200 dark:bg-primary/20 text-primary'
                  }`}>
                    <span className="material-symbols-outlined text-[14px]">
                      {getIconForType(trace.type)}
                    </span>
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-800 dark:text-slate-200">{trace.description}</p>
                    <p className="text-xs text-slate-500">{trace.source} → {trace.target}</p>
                  </div>
                </div>
              ))}

            </div>
          </div>
          
          <div className="border-t border-slate-200 dark:border-primary/10 pt-6 mt-auto">
            <h4 className="text-sm font-bold uppercase tracking-wider text-slate-400 mb-4">Node Metrics</h4>
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3 rounded-xl bg-slate-100 dark:bg-primary/5 border border-slate-200 dark:border-primary/10">
                <p className="text-[10px] text-slate-500">Events Processed</p>
                <p className="text-lg font-bold text-slate-800 dark:text-slate-200">{traces.length}</p>
              </div>
              <div className="p-3 rounded-xl bg-slate-100 dark:bg-primary/5 border border-slate-200 dark:border-primary/10">
                <p className="text-[10px] text-slate-500">Est. LLM Cost</p>
                <p className="text-lg font-bold text-slate-800 dark:text-slate-200">${(traces.filter(t => t.type === 'delegation' || t.type === 'synthesis').length * 0.001).toFixed(3)}</p>
              </div>
            </div>
          </div>
        </>
      )}
    </aside>
  );
};
