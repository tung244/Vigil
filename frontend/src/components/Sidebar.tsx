import { useEffect, useState } from 'react';
import type { GraphNodeStatus } from '../types';
import { fetchNodes } from '../services/api';

export const Sidebar = ({ selectedAgentId, onSelectAgent }: { selectedAgentId?: string | null, onSelectAgent?: (id: string | null) => void }) => {
  const [nodes, setNodes] = useState<GraphNodeStatus[]>([]);

  useEffect(() => {
    fetchNodes().then(setNodes);
    const interval = setInterval(() => {
      fetchNodes().then(setNodes);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside className="w-full lg:w-72 border-r border-slate-200 dark:border-primary/10 p-6 flex flex-col gap-6 overflow-y-auto bg-white/50 dark:bg-transparent">
      <div>
        <h1 className="text-xl font-black text-slate-900 dark:text-slate-100 mb-1">VIGIL</h1>
        <p className="text-slate-500 dark:text-slate-400 text-sm">.NET Tiered Analysis Pipeline</p>
      </div>
      <div className="space-y-2">
        <p className="text-xs font-bold uppercase tracking-wider text-slate-400">Active Agents</p>

        {nodes.map(node => (
          <div
            key={node.id}
            onClick={() => onSelectAgent ? onSelectAgent(selectedAgentId === node.id ? null : node.id) : null}
            className={`flex items-center gap-3 px-3 py-2 rounded-xl transition-all duration-300 cursor-pointer group ${
              selectedAgentId === node.id
                ? 'bg-primary text-white shadow-lg shadow-primary/20'
                : node.status === 'running'
                ? 'bg-primary/10 text-primary border border-primary/20 animate-pulse'
                : 'hover:bg-slate-100 dark:hover:bg-primary/10'
            }`}
          >
            <span className={`material-symbols-outlined transition-colors ${selectedAgentId === node.id ? '' : node.status === 'running' ? 'text-primary' : 'text-slate-400 group-hover:text-primary'}`}>
              {node.icon}
            </span>
            <div className="flex flex-col flex-1">
              <span className={`text-sm ${selectedAgentId === node.id ? 'font-bold' : 'font-medium'}`}>
                {node.name}
              </span>
              {node.status === 'running' && <span className="text-[10px] opacity-80 leading-none mt-0.5">{node.message || 'Processing...'}</span>}
            </div>
            {node.status === 'running' && (
              <span className="ml-auto flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
            )}
          </div>
        ))}
      </div>

      <div className="mt-auto p-4 rounded-xl bg-slate-100 dark:bg-primary/5 border border-slate-200 dark:border-primary/10">
        <p className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Node Status</p>
        <div className="flex items-center justify-between text-xs mb-1">
          <span>Active Agents</span>
          <span className="text-primary font-bold">{nodes.filter(n => n.status === 'running').length} / {nodes.length}</span>
        </div>
        <div className="w-full bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full overflow-hidden">
          <div className="bg-primary h-full transition-all duration-500" style={{ width: `${nodes.length > 0 ? (nodes.filter(n => n.status === 'completed').length / nodes.length) * 100 : 0}%` }}></div>
        </div>
      </div>
    </aside>
  );
};
